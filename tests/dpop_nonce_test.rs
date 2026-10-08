//! Server-provided DPoP nonces (RFC 9449 §8 for the AS, §9 for the resource server).

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::get, routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mcp_passport::auth::{OidcConfig, Timeouts};
use mcp_passport::config::AuthScheme;
use mcp_passport::crypto::DpopKey;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The `nonce` claim of the request's DPoP proof.
fn proof_nonce(headers: &HeaderMap) -> Option<String> {
    let proof = headers.get("dpop")?.to_str().ok()?;
    let claims = URL_SAFE_NO_PAD.decode(proof.split('.').nth(1)?).ok()?;
    let claims: Value = serde_json::from_slice(&claims).ok()?;
    claims.get("nonce")?.as_str().map(str::to_string)
}

/// A server-issued nonce: random, as a real server's would be.
fn fresh_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn nonce_challenge(nonce: &str) -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                "WWW-Authenticate",
                "DPoP error=\"use_dpop_nonce\"".to_string(),
            ),
            ("DPoP-Nonce", nonce.to_string()),
        ],
    )
        .into_response()
}

#[derive(Clone, Default)]
struct Counters {
    rpc: Arc<AtomicUsize>,
    token: Arc<AtomicUsize>,
    par: Arc<AtomicUsize>,
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    base
}

fn proxy(base: &str, vault: Vault) -> Arc<Proxy> {
    let (url_tx, _url_rx) = tokio::sync::oneshot::channel();
    Proxy::new(
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
        vault,
        "2025-11-25",
        AuthScheme::Dpop,
    )
}

fn vault_with(token: &str, refresh: Option<&str>) -> Vault {
    let vault = Vault::in_memory("nonce-test");
    vault.store_token("user", token).unwrap();
    vault
        .store_dpop_key("user", &DpopKey::generate().to_bytes())
        .unwrap();
    if let Some(r) = refresh {
        vault.store_refresh_token("user", r).unwrap();
    }
    vault
}

fn ping() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

#[tokio::test]
async fn test_resource_server_nonce_is_retried_without_reauth() {
    let counters = Counters::default();
    let nonce = fresh_nonce();
    let app = Router::new()
        .route(
            "/rpc",
            post(|State(c): State<Counters>, headers: HeaderMap| async move {
                c.rpc.fetch_add(1, Ordering::SeqCst);
                if proof_nonce(&headers) != Some(nonce.clone()) {
                    return nonce_challenge(&nonce);
                }
                Json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"})).into_response()
            }),
        )
        .route(
            "/par",
            post(|State(c): State<Counters>| async move {
                c.par.fetch_add(1, Ordering::SeqCst);
                StatusCode::BAD_REQUEST
            }),
        )
        .with_state(counters.clone());
    let base = serve(app).await;
    let p = proxy(&base, vault_with("token", None));

    let resp = p.call(ping()).await.unwrap().unwrap();
    assert_eq!(resp["result"], "ok");
    assert_eq!(counters.rpc.load(Ordering::SeqCst), 2);
    assert_eq!(
        counters.par.load(Ordering::SeqCst),
        0,
        "no re-authentication"
    );

    // The nonce is remembered for the next request.
    p.call(ping()).await.unwrap();
    assert_eq!(counters.rpc.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_resource_server_nonce_retry_happens_once() {
    let counters = Counters::default();
    let app = Router::new()
        .route(
            "/rpc",
            post(|State(c): State<Counters>| async move {
                // A fresh nonce every time: never satisfiable.
                c.rpc.fetch_add(1, Ordering::SeqCst);
                nonce_challenge(&fresh_nonce())
            }),
        )
        .with_state(counters.clone());
    let base = serve(app).await;
    let p = proxy(&base, vault_with("token", None));

    let err = p.call(ping()).await.unwrap_err().to_string();
    assert!(err.contains("use_dpop_nonce"), "{err}");
    assert_eq!(counters.rpc.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_authorization_server_nonce_on_refresh() {
    let counters = Counters::default();
    let nonce = fresh_nonce();
    let app = Router::new()
        .route(
            "/rpc",
            post(|headers: HeaderMap| async move {
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                if auth == "DPoP fresh" {
                    Json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"})).into_response()
                } else {
                    (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "DPoP")]).into_response()
                }
            }),
        )
        .route(
            "/token",
            post(
                |State(c): State<Counters>,
                 headers: HeaderMap,
                 Form(form): Form<HashMap<String, String>>| async move {
                    c.token.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(form["grant_type"], "refresh_token");
                    if proof_nonce(&headers) != Some(nonce.clone()) {
                        return (
                            StatusCode::BAD_REQUEST,
                            [("DPoP-Nonce", nonce)],
                            Json(json!({"error": "use_dpop_nonce"})),
                        )
                            .into_response();
                    }
                    Json(json!({"access_token": "fresh", "token_type": "DPoP"})).into_response()
                },
            ),
        )
        .route("/auth", get(|| async { StatusCode::NOT_FOUND }))
        .with_state(counters.clone());
    let base = serve(app).await;
    let vault = vault_with("stale", Some("r-1"));
    let p = proxy(&base, vault.clone());

    let resp = tokio::time::timeout(Duration::from_secs(5), p.call(ping()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(resp["result"], "ok");
    assert_eq!(counters.token.load(Ordering::SeqCst), 2);
    assert_eq!(vault.get_token("user").unwrap().as_deref(), Some("fresh"));
}
