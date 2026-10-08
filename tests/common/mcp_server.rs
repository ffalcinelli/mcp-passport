//! A strict MCP Streamable HTTP server for tests, speaking both eras:
//!
//! - **2026-07-28** (modern): per-request `_meta`, header/body validation
//!   (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `x-mcp-header`),
//!   `server/discover`, `subscriptions/listen`, no sessions, 405 for GET.
//! - **2025-11-25** (legacy): `initialize`, `Mcp-Session-Id`, GET stream.
//!
//! It can also act as an OAuth protected resource (RFC 9728) whose tokens are
//! validated through an introspection endpoint (e.g. Keycloak), including the
//! DPoP proof: signature, `cnf.jkt` binding, `htm`/`htu` and `ath`.

// Handlers short-circuit with ready-made HTTP responses.
#![allow(clippy::result_large_err)]

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MODERN: &str = "2026-07-28";
pub const LEGACY: &str = "2025-11-25";
const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const SESSION: &str = "sess-1";

/// Token introspection (RFC 7662) used to validate access tokens.
#[derive(Clone, Debug)]
pub struct Introspection {
    pub url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug, Default)]
pub struct ServerOptions {
    /// Authorization server advertised in the protected resource metadata.
    pub issuer: Option<String>,
    /// When set, every POST needs a valid DPoP-bound token.
    pub introspection: Option<Introspection>,
    /// Reject this many otherwise valid requests with 401 (forces a refresh).
    pub reject_valid_tokens: usize,
}

#[derive(Debug, Clone)]
pub struct Recorded {
    pub http_method: String,
    pub headers: HashMap<String, String>,
    pub body: Value,
}

#[derive(Debug, Default)]
pub struct Log {
    pub requests: Vec<Recorded>,
    /// Ids of streamed responses whose client went away (cancellation).
    pub streams_closed: Vec<Value>,
    /// Why requests were rejected.
    pub rejections: Vec<String>,
}

#[derive(Clone)]
pub struct McpServer {
    pub base: String,
    pub log: Arc<Mutex<Log>>,
    reject_left: Arc<AtomicUsize>,
}

impl McpServer {
    /// The MCP endpoint.
    pub fn url(&self) -> String {
        format!("{}/mcp", self.base)
    }

    /// The recorded POST bodies with this JSON-RPC method.
    pub fn posted(&self, method: &str) -> Vec<Recorded> {
        self.log
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.http_method == "POST" && r.body["method"] == method)
            .cloned()
            .collect()
    }

    pub fn gets(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.http_method == "GET")
            .count()
    }

    pub fn streams_closed(&self) -> Vec<Value> {
        self.log.lock().unwrap().streams_closed.clone()
    }

    pub fn rejections(&self) -> Vec<String> {
        self.log.lock().unwrap().rejections.clone()
    }

    /// Rejects the next `n` otherwise valid requests with 401 `invalid_token`.
    pub fn reject_next(&self, n: usize) {
        self.reject_left.store(n, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct AppState {
    base: String,
    options: ServerOptions,
    log: Arc<Mutex<Log>>,
    reject_left: Arc<AtomicUsize>,
    http: reqwest::Client,
}

pub async fn start(options: ServerOptions) -> McpServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let log: Arc<Mutex<Log>> = Arc::default();
    let reject_left = Arc::new(AtomicUsize::new(options.reject_valid_tokens));
    let state = AppState {
        base: base.clone(),
        reject_left: reject_left.clone(),
        options,
        log: log.clone(),
        http: reqwest::Client::new(),
    };
    let app = Router::new()
        .route(
            "/mcp",
            post(mcp_post)
                .get(mcp_get)
                .delete(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    McpServer {
        base,
        log,
        reject_left,
    }
}

async fn resource_metadata(State(s): State<AppState>) -> Response {
    let Some(issuer) = &s.options.issuer else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(json!({
        "resource": format!("{}/mcp", s.base),
        "authorization_servers": [issuer],
        "scopes_supported": ["mcp:tools"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Strict MCP 2026-07-28 Server"
    }))
    .into_response()
}

fn header_map(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

fn rpc_error(status: StatusCode, id: &Value, code: i64, message: &str, data: Value) -> Response {
    let mut error = json!({"code": code, "message": message});
    if !data.is_null() {
        error["data"] = data;
    }
    (
        status,
        Json(json!({"jsonrpc": "2.0", "id": id, "error": error})),
    )
        .into_response()
}

fn result(id: &Value, mut result: Value) -> Response {
    result["resultType"] = json!("complete");
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

/// Decodes the `=?base64?…?=` header form.
fn decode_header(value: &str) -> Option<String> {
    match value
        .strip_prefix("=?base64?")
        .and_then(|v| v.strip_suffix("?="))
    {
        Some(encoded) => String::from_utf8(STANDARD.decode(encoded).ok()?).ok(),
        None => Some(value.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Validates the access token and its DPoP proof. Returns the token's scopes.
async fn check_auth(s: &AppState, headers: &HeaderMap, htm: &str) -> Result<Vec<String>, Response> {
    let Some(introspection) = &s.options.introspection else {
        return Ok(Vec::new());
    };
    let reject = |why: String, error: Option<&str>| {
        s.log.lock().unwrap().rejections.push(why);
        let mut challenge = format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:tools\"",
            s.base
        );
        if let Some(e) = error {
            challenge.push_str(&format!(", error=\"{e}\""));
        }
        (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", challenge)]).into_response()
    };

    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let Some(token) = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("DPoP "))
    else {
        return Err(reject("no access token".into(), None));
    };
    let Some(proof) = headers.get("dpop").and_then(|v| v.to_str().ok()) else {
        return Err(reject("no DPoP proof".into(), Some("invalid_token")));
    };

    let introspected: Value = match s
        .http
        .post(&introspection.url)
        .basic_auth(&introspection.client_id, Some(&introspection.client_secret))
        .form(&[("token", token)])
        .send()
        .await
    {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(e) => return Err(reject(format!("introspection failed: {e}"), None)),
    };
    if introspected["active"] != true {
        return Err(reject(
            format!("token not active: {introspected}"),
            Some("invalid_token"),
        ));
    }
    let jkt = introspected["cnf"]["jkt"].as_str().unwrap_or_default();
    if let Err(why) = verify_dpop_proof(proof, htm, &format!("{}/mcp", s.base), token, jkt) {
        return Err(reject(
            format!("bad DPoP proof: {why}"),
            Some("invalid_token"),
        ));
    }
    if s.reject_left
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok()
    {
        return Err(reject("forced rejection".into(), Some("invalid_token")));
    }
    Ok(introspected["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect())
}

/// Checks a DPoP proof (RFC 9449 §4.3): signature with the embedded key, the
/// key's thumbprint against the token's `cnf.jkt`, `htm`, `htu` and `ath`.
fn verify_dpop_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    token: &str,
    jkt: &str,
) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err("not a JWT".into());
    }
    let decode = |p: &str| -> Result<Value, String> {
        let bytes = URL_SAFE_NO_PAD.decode(p).map_err(|e| e.to_string())?;
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    };
    let header = decode(parts[0])?;
    let claims = decode(parts[1])?;
    if header["typ"] != "dpop+jwt" || header["alg"] != "ES256" {
        return Err("wrong typ/alg".into());
    }
    let (x, y) = (
        header["jwk"]["x"].as_str().unwrap_or_default(),
        header["jwk"]["y"].as_str().unwrap_or_default(),
    );
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    if URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())) != jkt {
        return Err("key does not match cnf.jkt".into());
    }
    let coord = |c: &str| -> Result<p256::FieldBytes, String> {
        let bytes = URL_SAFE_NO_PAD.decode(c).map_err(|e| e.to_string())?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| "bad coordinate".to_string())?;
        Ok(array.into())
    };
    let point = p256::EncodedPoint::from_affine_coordinates(&coord(x)?, &coord(y)?, false);
    let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point).map_err(|e| e.to_string())?;
    let sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| e.to_string())?;
    let sig = p256::ecdsa::Signature::from_slice(&sig).map_err(|e| e.to_string())?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .map_err(|_| "bad signature".to_string())?;
    if claims["htm"] != htm || claims["htu"] != htu {
        return Err(format!(
            "htm/htu mismatch: {} {}",
            claims["htm"], claims["htu"]
        ));
    }
    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    if claims["ath"] != ath.as_str() {
        return Err("ath mismatch".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Streamable HTTP
// ---------------------------------------------------------------------------

/// Records the id of a streamed response when the stream is dropped.
struct CloseRecorder(Arc<Mutex<Log>>, Value);
impl Drop for CloseRecorder {
    fn drop(&mut self) {
        if let Ok(mut log) = self.0.lock() {
            log.streams_closed.push(self.1.clone());
        }
    }
}

/// An SSE response sending `first`, then `every` forever, until the client
/// disconnects (which records `id` as closed).
fn endless_stream(
    log: Arc<Mutex<Log>>,
    id: Value,
    first: Vec<Value>,
    every: Option<Value>,
) -> Response {
    let recorder = CloseRecorder(log, id);
    let initial = futures::stream::iter(
        first
            .into_iter()
            .map(|m| Ok::<_, std::convert::Infallible>(Event::default().data(m.to_string()))),
    );
    let rest = futures::stream::unfold((recorder, every), |(r, every)| async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let event = match &every {
            Some(m) => Event::default().data(m.to_string()),
            None => Event::default().comment("keep-alive"),
        };
        Some((Ok(event), (r, every)))
    });
    use futures::StreamExt;
    Sse::new(initial.chain(rest))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn tools() -> Value {
    json!([
        {"name": "sql", "description": "Runs SQL in a region", "inputSchema": {
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "query": {"type": "string"}
            },
            "required": ["region", "query"]
        }},
        {"name": "admin_tool", "description": "Needs the mcp:admin scope",
         "inputSchema": {"type": "object"}},
        {"name": "slow", "description": "Streams progress forever",
         "inputSchema": {"type": "object"}},
        {"name": "broken", "description": "Invalid x-mcp-header on a number",
         "inputSchema": {"type": "object", "properties": {
            "n": {"type": "number", "x-mcp-header": "N"}}}}
    ])
}

/// Validates the 2026-07-28 request headers against the body.
fn check_modern_headers(headers: &HashMap<String, String>, body: &Value) -> Result<(), Response> {
    let id = &body["id"];
    let mismatch = |why: String| {
        rpc_error(
            StatusCode::BAD_REQUEST,
            id,
            -32020,
            &format!("Header mismatch: {why}"),
            Value::Null,
        )
    };
    let version = body["params"]["_meta"][META_VERSION]
        .as_str()
        .unwrap_or_default();
    if headers.get("mcp-protocol-version").map(String::as_str) != Some(version) {
        return Err(mismatch("MCP-Protocol-Version".into()));
    }
    if version != MODERN && version != LEGACY {
        return Err(rpc_error(
            StatusCode::BAD_REQUEST,
            id,
            -32022,
            "Unsupported protocol version",
            json!({"supported": [MODERN, LEGACY], "requested": version}),
        ));
    }
    let method = body["method"].as_str().unwrap_or_default();
    if headers.get("mcp-method").map(String::as_str) != Some(method) {
        return Err(mismatch("Mcp-Method".into()));
    }
    let name_field = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    if let Some(field) = name_field {
        let header = headers.get("mcp-name").and_then(|h| decode_header(h));
        if header.as_deref() != body["params"][field].as_str() {
            return Err(mismatch("Mcp-Name".into()));
        }
    }
    if method == "tools/call" && body["params"]["name"] == "sql" {
        let header = headers
            .get("mcp-param-region")
            .and_then(|h| decode_header(h));
        if header.as_deref() != body["params"]["arguments"]["region"].as_str() {
            return Err(mismatch("Mcp-Param-Region".into()));
        }
    }
    Ok(())
}

async fn mcp_post(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let map = header_map(&headers);
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    s.log.lock().unwrap().requests.push(Recorded {
        http_method: "POST".into(),
        headers: map.clone(),
        body: body.clone(),
    });

    let scopes = match check_auth(&s, &headers, "POST").await {
        Ok(scopes) => scopes,
        Err(response) => return response,
    };

    let modern = body["params"]["_meta"][META_VERSION].is_string();
    if modern {
        if let Err(response) = check_modern_headers(&map, &body) {
            return response;
        }
    }
    let id = body["id"].clone();
    if id.is_null() {
        // Notifications (e.g. a legacy notifications/cancelled).
        return StatusCode::ACCEPTED.into_response();
    }
    let method = body["method"].as_str().unwrap_or_default();

    if !modern {
        if method == "initialize" {
            return (
                [("mcp-session-id", SESSION)],
                Json(json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": LEGACY,
                    "capabilities": {"tools": {"listChanged": true}},
                    "serverInfo": {"name": "strict-mcp", "version": "1.0.0"}
                }})),
            )
                .into_response();
        }
        if map.get("mcp-session-id").map(String::as_str) != Some(SESSION) {
            return (StatusCode::BAD_REQUEST, "missing or unknown session").into_response();
        }
    }

    match method {
        "server/discover" if modern => result(
            &id,
            json!({
                "supportedVersions": [MODERN, LEGACY],
                "capabilities": {"tools": {"listChanged": true}},
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "strict-mcp", "version": "1.0.0"}},
                "ttlMs": 60000,
                "cacheScope": "public"
            }),
        ),
        "tools/list" => result(
            &id,
            json!({"tools": tools(), "ttlMs": 60000, "cacheScope": "private"}),
        ),
        "tools/call" => match body["params"]["name"].as_str() {
            Some("sql") => result(
                &id,
                json!({"content": [{"type": "text",
                "text": format!("region={}", body["params"]["arguments"]["region"].as_str().unwrap_or_default())}]}),
            ),
            Some("admin_tool") => {
                if s.options.introspection.is_some() && !scopes.iter().any(|x| x == "mcp:admin") {
                    s.log
                        .lock()
                        .unwrap()
                        .rejections
                        .push("insufficient scope".into());
                    let challenge = format!(
                        "Bearer error=\"insufficient_scope\", scope=\"mcp:admin\", resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp\"",
                        s.base
                    );
                    return (StatusCode::FORBIDDEN, [("WWW-Authenticate", challenge)])
                        .into_response();
                }
                result(
                    &id,
                    json!({"content": [{"type": "text", "text": "admin ok"}]}),
                )
            }
            Some("slow") => endless_stream(
                s.log.clone(),
                id.clone(),
                vec![],
                Some(json!({"jsonrpc": "2.0", "method": "notifications/progress",
                    "params": {"progressToken": id, "progress": 1}})),
            ),
            _ => rpc_error(StatusCode::OK, &id, -32602, "Unknown tool", Value::Null),
        },
        "subscriptions/listen" if modern => {
            let sub = json!({"io.modelcontextprotocol/subscriptionId": id});
            endless_stream(
                s.log.clone(),
                id.clone(),
                vec![
                    json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
                        "params": {"_meta": sub, "notifications": body["params"]["notifications"]}}),
                    json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed",
                        "params": {"_meta": sub}}),
                ],
                None,
            )
        }
        _ => rpc_error(
            StatusCode::NOT_FOUND,
            &id,
            -32601,
            "Method not found",
            Value::Null,
        ),
    }
}

async fn mcp_get(State(s): State<AppState>, headers: HeaderMap) -> Response {
    s.log.lock().unwrap().requests.push(Recorded {
        http_method: "GET".into(),
        headers: header_map(&headers),
        body: Value::Null,
    });
    // Only legacy sessions have a standalone GET stream.
    if headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) != Some(SESSION) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if let Err(response) = check_auth(&s, &headers, "GET").await {
        return response;
    }
    endless_stream(
        s.log.clone(),
        json!("legacy-get"),
        vec![json!({"jsonrpc": "2.0", "method": "notifications/message",
            "params": {"level": "info", "data": "legacy stream"}})],
        None,
    )
}
