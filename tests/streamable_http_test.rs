//! MCP Streamable HTTP behaviour of the proxy, against small in-process servers.

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::get, routing::post, Router};
use mcp_passport::auth::{OidcConfig, Timeouts};
use mcp_passport::config::AuthScheme;
use mcp_passport::crypto::DpopKey;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{}", addr)
}

/// A proxy whose vault already holds a token, so no auth flow runs.
fn authed_proxy(url: &str) -> Arc<Proxy> {
    let vault = Vault::in_memory("streamable-http-test");
    vault.store_token("user", "valid_token").unwrap();
    vault
        .store_dpop_key("user", &DpopKey::generate().to_bytes())
        .unwrap();
    Proxy::new(
        url,
        "user",
        OidcConfig {
            client_id: "c".into(),
            redirect_url: "http://127.0.0.1:1/callback".into(),
            timeouts: Timeouts::fast(),
            ..Default::default()
        },
        vault,
        "2025-11-25",
        AuthScheme::Bearer,
    )
}

async fn collect(proxy: &Proxy, payload: Value) -> (anyhow::Result<()>, Vec<Value>) {
    let (tx, mut rx) = mpsc::channel(16);
    let res = proxy.handle_request(payload, &tx).await;
    drop(tx);
    let mut out = Vec::new();
    while let Some(m) = rx.recv().await {
        out.push(serde_json::from_str(&m).unwrap());
    }
    (res, out)
}

fn sse_response(events: &[Value]) -> axum::response::Response {
    let body: String = events
        .iter()
        .enumerate()
        .map(|(i, e)| format!("id: {i}\nevent: message\ndata: {e}\n\n"))
        .collect();
    ([("content-type", "text/event-stream")], body).into_response()
}

#[tokio::test]
async fn test_post_sends_accept_header_for_json_and_sse() {
    let seen = Arc::new(Mutex::new(None::<String>));
    let seen_c = seen.clone();
    let app = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap| {
            let seen = seen_c.clone();
            async move {
                *seen.lock().unwrap() = headers
                    .get("accept")
                    .map(|v| v.to_str().unwrap().to_string());
                axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
            }
        }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    proxy
        .call(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("application/json, text/event-stream")
    );
}

#[tokio::test]
async fn test_sse_post_response_forwards_every_event() {
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            sse_response(&[
                json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}),
                json!({"jsonrpc": "2.0", "id": 5, "result": {"tools": []}}),
            ])
        }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));

    let (res, out) = collect(
        &proxy,
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
    )
    .await;
    res.unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0]["method"], "notifications/progress");
    assert_eq!(out[1]["id"], 5);

    // `call` picks the response out of the stream.
    let resp = proxy
        .call(json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp["result"]["tools"], json!([]));
}

#[tokio::test]
async fn test_sse_post_response_without_answer_is_an_error() {
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            sse_response(&[json!({"jsonrpc": "2.0", "method": "notifications/progress"})])
        }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let (res, out) = collect(
        &proxy,
        json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call"}),
    )
    .await;
    assert_eq!(out.len(), 1);
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("ended before the response"));
}

#[tokio::test]
async fn test_accepted_forwards_nothing() {
    let app = Router::new().route("/mcp", post(|| async { StatusCode::ACCEPTED }));
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let (res, out) = collect(
        &proxy,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    res.unwrap();
    assert!(out.is_empty());
}

#[tokio::test]
async fn test_http_error_is_reported() {
    let app = Router::new().route(
        "/mcp",
        post(|| async { (StatusCode::BAD_GATEWAY, "upstream down") }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let err = proxy
        .call(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("502"), "{err}");
    assert!(err.contains("upstream down"), "{err}");
}

#[tokio::test]
async fn test_jsonrpc_error_in_non_2xx_body_is_passed_through() {
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "jsonrpc": "2.0", "id": 1,
                    "error": {"code": -32600, "message": "Invalid Request"}
                })),
            )
        }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let resp = proxy
        .call(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp["error"]["code"], -32600);
}

#[tokio::test]
async fn test_404_with_session_clears_session() {
    let calls = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let calls_c = calls.clone();
    let app = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap| {
            let calls = calls_c.clone();
            async move {
                let sid = headers
                    .get("mcp-session-id")
                    .map(|v| v.to_str().unwrap().to_string());
                calls.lock().unwrap().push(sid.clone());
                match sid {
                    None => (
                        [("mcp-session-id", "s-1")],
                        axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
                    )
                        .into_response(),
                    Some(_) => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});

    proxy.call(msg.clone()).await.unwrap();
    let err = proxy.call(msg.clone()).await.unwrap_err().to_string();
    assert!(err.contains("session expired"), "{err}");
    // The stale session id is not sent again.
    proxy.call(msg).await.unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls[0], None);
    assert_eq!(calls[1].as_deref(), Some("s-1"));
    assert_eq!(calls[2], None);
}

#[tokio::test]
async fn test_legacy_session_signal() {
    let (url, _seen) = header_recorder().await;
    let proxy = authed_proxy(&url);

    let p = proxy.clone();
    let waiter = tokio::spawn(async move { p.wait_for_legacy_session().await });

    // Modern traffic never establishes a legacy session (no GET stream).
    proxy
        .call(modern(1, "tools/list", json!({})))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!waiter.is_finished());

    proxy
        .call(json!({"jsonrpc": "2.0", "id": 2, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}}}))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_modern_404_is_a_jsonrpc_error_not_session_expiry() {
    let app = Router::new().route(
        "/mcp",
        post(|axum::Json(body): axum::Json<Value>| async move {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"jsonrpc": "2.0", "id": body["id"],
                "error": {"code": -32601, "message": "Method not found"}})),
            )
        }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let resp = proxy
        .call(modern(1, "unknown/method", json!({})))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn test_listen_sse_stops_on_405() {
    let app = Router::new().route("/mcp", get(|| async { StatusCode::METHOD_NOT_ALLOWED }));
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let (tx, _rx) = mpsc::channel(4);
    let res = timeout(
        Duration::from_secs(2),
        proxy.listen_sse(&format!("{base}/mcp"), tx),
    )
    .await
    .expect("listener should stop on 405");
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_listen_sse_resumes_with_last_event_id() {
    let seen = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let seen_c = seen.clone();
    let app = Router::new().route(
        "/mcp",
        get(move |headers: HeaderMap| {
            let seen = seen_c.clone();
            async move {
                let last = headers
                    .get("last-event-id")
                    .map(|v| v.to_str().unwrap().to_string());
                let n = {
                    let mut s = seen.lock().unwrap();
                    s.push(last);
                    s.len()
                };
                // Each connection delivers one event, then closes.
                let body = format!(
                    "id: evt-{n}\ndata: {}\n\n",
                    json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"n": n}})
                );
                ([("content-type", "text/event-stream")], body)
            }
        }),
    );
    let base = serve(app).await;
    let proxy = authed_proxy(&format!("{base}/mcp"));
    let (tx, mut rx) = mpsc::channel(4);
    let p = proxy.clone();
    let url = format!("{base}/mcp");
    let handle = tokio::spawn(async move { p.listen_sse(&url, tx).await });

    for _ in 0..2 {
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    handle.abort();

    let seen = seen.lock().unwrap();
    assert_eq!(seen[0], None);
    assert_eq!(seen[1].as_deref(), Some("evt-1"));
}

type Seen = Arc<Mutex<Vec<HashMap<String, String>>>>;

/// A server that records the headers of each POST and answers `initialize`
/// with a negotiated version and a session id.
async fn header_recorder() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let app = Router::new().route(
        "/mcp",
        post(
            move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
                let s = s.clone();
                async move {
                    let map = headers
                        .iter()
                        .map(|(k, v)| {
                            (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                        })
                        .collect();
                    s.lock().unwrap().push(map);
                    if body["method"] == "initialize" {
                        return (
                            [("mcp-session-id", "legacy-1")],
                            axum::Json(json!({"jsonrpc": "2.0", "id": body["id"],
                            "result": {"protocolVersion": "2025-06-18"}})),
                        )
                            .into_response();
                    }
                    axum::Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {}}))
                        .into_response()
                }
            },
        ),
    );
    (format!("{}/mcp", serve(app).await), seen)
}

fn modern(id: u64, method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

#[tokio::test]
async fn test_modern_request_headers() {
    let (url, seen) = header_recorder().await;
    let proxy = authed_proxy(&url);

    proxy
        .call(modern(
            1,
            "tools/call",
            json!({"name": "get_weather", "arguments": {}}),
        ))
        .await
        .unwrap();
    proxy
        .call(modern(
            2,
            "resources/read",
            json!({"uri": "file:///café.txt"}),
        ))
        .await
        .unwrap();
    proxy
        .call(modern(3, "tools/list", json!({})))
        .await
        .unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen[0]["mcp-protocol-version"], "2026-07-28");
    assert_eq!(seen[0]["mcp-method"], "tools/call");
    assert_eq!(seen[0]["mcp-name"], "get_weather");
    assert_eq!(seen[1]["mcp-name"], "=?base64?ZmlsZTovLy9jYWbDqS50eHQ=?=");
    assert_eq!(seen[2]["mcp-method"], "tools/list");
    assert!(!seen[2].contains_key("mcp-name"));
}

#[tokio::test]
async fn test_legacy_negotiated_version_and_session() {
    let (url, seen) = header_recorder().await;
    let proxy = authed_proxy(&url);

    proxy
        .call(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}}}))
        .await
        .unwrap();
    proxy
        .call(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await
        .unwrap();
    // A modern request on the same proxy never carries the legacy session.
    proxy
        .call(modern(3, "tools/list", json!({})))
        .await
        .unwrap();

    let seen = seen.lock().unwrap();
    // `initialize` announces the version it requests...
    assert_eq!(seen[0]["mcp-protocol-version"], "2025-11-25");
    // ...later legacy requests use the negotiated one, with the session.
    assert_eq!(seen[1]["mcp-protocol-version"], "2025-06-18");
    assert_eq!(seen[1]["mcp-session-id"], "legacy-1");
    assert_eq!(seen[2]["mcp-protocol-version"], "2026-07-28");
    assert!(!seen[2].contains_key("mcp-session-id"));
}

/// A server whose `region` parameter is mirrored into `Mcp-Param-Region`.
/// `schema_version` switches the annotation name, as if the server changed
/// the tool after the client listed it.
async fn x_mcp_header_server(schema_version: Arc<Mutex<u32>>) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let s = seen.clone();
    let app = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
            let (s, schema_version) = (s.clone(), schema_version.clone());
            async move {
                let map: HashMap<String, String> = headers
                    .iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                s.lock().unwrap().push(map.clone());
                let header = if *schema_version.lock().unwrap() == 1 { "Region" } else { "Zone" };
                match body["method"].as_str() {
                    Some("tools/list") => axum::Json(json!({"jsonrpc": "2.0", "id": body["id"],
                        "result": {"tools": [
                            {"name": "sql", "inputSchema": {"type": "object", "properties": {
                                "region": {"type": "string", "x-mcp-header": header},
                                "query": {"type": "string"}}}},
                            {"name": "broken", "inputSchema": {"type": "object", "properties": {
                                "n": {"type": "number", "x-mcp-header": "N"}}}},
                            {"name": "plain", "inputSchema": {"type": "object"}}
                        ]}}))
                    .into_response(),
                    Some("tools/call") => {
                        let expected = format!("mcp-param-{}", header.to_lowercase());
                        if map.get(&expected).map(String::as_str) != body["params"]["arguments"]["region"].as_str() {
                            return (StatusCode::BAD_REQUEST, axum::Json(json!({"jsonrpc": "2.0",
                                "id": body["id"], "error": {"code": -32020, "message": "Header mismatch"}})))
                                .into_response();
                        }
                        axum::Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"ok": true}}))
                            .into_response()
                    }
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }),
    );
    (format!("{}/mcp", serve(app).await), seen)
}

fn sql_call(id: u64) -> Value {
    modern(
        id,
        "tools/call",
        json!({"name": "sql", "arguments": {"region": "us-west1", "query": "SELECT 1"}}),
    )
}

#[tokio::test]
async fn test_x_mcp_header_mirrored_and_invalid_tools_dropped() {
    let (url, seen) = x_mcp_header_server(Arc::new(Mutex::new(1))).await;
    let proxy = authed_proxy(&url);

    let list = proxy
        .call(modern(1, "tools/list", json!({})))
        .await
        .unwrap()
        .unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["sql", "plain"],
        "the invalid tool is filtered out"
    );

    let resp = proxy.call(sql_call(2)).await.unwrap().unwrap();
    assert_eq!(resp["result"]["ok"], true);
    assert_eq!(seen.lock().unwrap()[1]["mcp-param-region"], "us-west1");
}

#[tokio::test]
async fn test_header_mismatch_refreshes_tools_and_retries() {
    let version = Arc::new(Mutex::new(1));
    let (url, seen) = x_mcp_header_server(version.clone()).await;
    let proxy = authed_proxy(&url);

    proxy
        .call(modern(1, "tools/list", json!({})))
        .await
        .unwrap();
    // The server renames the header; our cached annotation is now stale.
    *version.lock().unwrap() = 2;

    let resp = proxy.call(sql_call(2)).await.unwrap().unwrap();
    assert_eq!(resp["result"]["ok"], true);

    let seen = seen.lock().unwrap();
    let methods: Vec<&str> = seen.iter().map(|h| h["mcp-method"].as_str()).collect();
    // list, rejected call, refresh list, retried call
    assert_eq!(
        methods,
        vec!["tools/list", "tools/call", "tools/list", "tools/call"]
    );
    assert_eq!(seen[3]["mcp-param-zone"], "us-west1");
    // The refresh carries the protocol metadata of the original request.
    assert_eq!(seen[2]["mcp-protocol-version"], "2026-07-28");
}
