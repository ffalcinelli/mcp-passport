//! Silent token refresh (RFC 6749 §6 with DPoP, RFC 9449 §5).

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::post, Json, Router};
use mcp_passport::auth::{OidcConfig, Timeouts};
use mcp_passport::config::AuthScheme;
use mcp_passport::crypto::DpopKey;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
struct Server {
    /// Status returned for a request with the old token (401 or 403).
    reject_old_with: Arc<std::sync::Mutex<Option<StatusCode>>>,
    accept_refresh: bool,
    /// Accept the old token too (so only a proactive refresh replaces it).
    accept_old: bool,
    refresh_calls: Arc<AtomicUsize>,
    par_calls: Arc<AtomicUsize>,
    par_forms: Arc<std::sync::Mutex<Vec<HashMap<String, String>>>>,
}

async fn rpc(State(s): State<Server>, headers: HeaderMap) -> axum::response::Response {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if auth == "Bearer new-token" {
        return Json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"})).into_response();
    }
    if s.accept_old && auth == "Bearer old-token" {
        return Json(json!({"jsonrpc": "2.0", "id": 1, "result": "old"})).into_response();
    }
    match *s.reject_old_with.lock().unwrap() {
        Some(StatusCode::FORBIDDEN) => (
            StatusCode::FORBIDDEN,
            [(
                "WWW-Authenticate",
                "Bearer error=\"insufficient_scope\", scope=\"admin\"",
            )],
        )
            .into_response(),
        _ => (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Bearer error=\"invalid_token\"")],
        )
            .into_response(),
    }
}

async fn token(
    State(s): State<Server>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> axum::response::Response {
    assert!(
        headers.contains_key("dpop"),
        "token request without DPoP proof"
    );
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("refresh_token")
    );
    assert!(form.contains_key("resource"));
    s.refresh_calls.fetch_add(1, Ordering::SeqCst);
    if s.accept_refresh && form.get("refresh_token").map(String::as_str) == Some("r-1") {
        Json(json!({
            "access_token": "new-token",
            "token_type": "DPoP",
            "refresh_token": "r-2"
        }))
        .into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response()
    }
}

async fn par(
    State(s): State<Server>,
    Form(form): Form<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    s.par_calls.fetch_add(1, Ordering::SeqCst);
    s.par_forms.lock().unwrap().push(form);
    Json(json!({"request_uri": "urn:ietf:params:oauth:request_uri:x", "expires_in": 60}))
}

async fn setup(server: Server) -> (Arc<Proxy>, Vault) {
    let app = Router::new()
        .route("/rpc", post(rpc))
        .route("/token", post(token))
        .route("/par", post(par))
        .with_state(server);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let vault = Vault::in_memory("refresh-test");
    vault.store_token("user", "old-token").unwrap();
    vault
        .store_dpop_key("user", &DpopKey::generate().to_bytes())
        .unwrap();
    vault.store_refresh_token("user", "r-1").unwrap();

    // A listener on the auth URL keeps the test from opening a browser.
    let (url_tx, _url_rx) = tokio::sync::oneshot::channel();
    let proxy = Proxy::new(
        &format!("{base}/rpc"),
        "user",
        OidcConfig {
            client_id: "c".into(),
            redirect_url: "http://127.0.0.1:0/callback".into(),
            auth_url_override: Some(format!("{base}/auth")),
            token_url_override: Some(format!("{base}/token")),
            par_url_override: Some(format!("{base}/par")),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(Some(url_tx))),
            timeouts: Timeouts::fast(),
            ..Default::default()
        },
        vault.clone(),
        "2025-11-25",
        AuthScheme::Bearer,
    );
    (proxy, vault)
}

fn ping() -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

#[tokio::test]
async fn test_expired_token_is_refreshed_without_login() {
    let server = Server {
        accept_refresh: true,
        ..Default::default()
    };
    let (proxy, vault) = setup(server.clone()).await;

    let resp = proxy.call(ping()).await.unwrap().unwrap();
    assert_eq!(resp["result"], "ok");

    assert_eq!(server.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        server.par_calls.load(Ordering::SeqCst),
        0,
        "no browser login"
    );
    assert_eq!(
        vault.get_token("user").unwrap().as_deref(),
        Some("new-token")
    );
    // The rotated refresh token replaces the old one.
    assert_eq!(
        vault.get_refresh_token("user").unwrap().as_deref(),
        Some("r-2")
    );
}

#[tokio::test]
async fn test_rejected_refresh_falls_back_to_login() {
    let server = Server::default();
    let (proxy, vault) = setup(server.clone()).await;

    // The login cannot complete (nobody visits the URL), so the call fails,
    // but only after the refresh was rejected and a PAR request was made.
    assert!(proxy.call(ping()).await.is_err());
    assert_eq!(server.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.par_calls.load(Ordering::SeqCst), 1);
    assert_eq!(vault.get_refresh_token("user").unwrap(), None);
    // The PAR request binds the code to the new DPoP key (RFC 9449 §10).
    let forms = server.par_forms.lock().unwrap();
    assert_eq!(forms[0]["dpop_jkt"].len(), 43);
    assert_eq!(forms[0]["code_challenge_method"], "S256");
    // The old credentials are left in place.
    assert_eq!(
        vault.get_token("user").unwrap().as_deref(),
        Some("old-token")
    );
}

#[tokio::test]
async fn test_step_up_never_uses_refresh() {
    let server = Server {
        accept_refresh: true,
        ..Default::default()
    };
    *server.reject_old_with.lock().unwrap() = Some(StatusCode::FORBIDDEN);
    let (proxy, vault) = setup(server.clone()).await;

    assert!(proxy.call(ping()).await.is_err());
    assert_eq!(server.refresh_calls.load(Ordering::SeqCst), 0);
    assert_eq!(server.par_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        vault.get_refresh_token("user").unwrap().as_deref(),
        Some("r-1")
    );
}

fn expired_meta() -> mcp_passport::vault::CredentialMeta {
    mcp_passport::vault::CredentialMeta {
        expires_at: Some(1),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_expiring_token_is_refreshed_before_the_request() {
    let server = Server {
        accept_refresh: true,
        accept_old: true,
        ..Default::default()
    };
    let (proxy, vault) = setup(server.clone()).await;
    vault.store_meta("user", &expired_meta()).unwrap();

    let resp = proxy.call(ping()).await.unwrap().unwrap();
    assert_eq!(resp["result"], "ok", "the request used the refreshed token");
    assert_eq!(server.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.par_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_failed_proactive_refresh_keeps_the_token_and_never_logs_in() {
    let server = Server {
        accept_old: true,
        ..Default::default()
    };
    let (proxy, vault) = setup(server.clone()).await;
    vault.store_meta("user", &expired_meta()).unwrap();

    for _ in 0..2 {
        let resp = proxy.call(ping()).await.unwrap().unwrap();
        assert_eq!(resp["result"], "old");
    }
    // Tried once per credential generation, and no interactive login.
    assert_eq!(server.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(server.par_calls.load(Ordering::SeqCst), 0);
}
