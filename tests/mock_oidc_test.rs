use anyhow::Context;
use axum::{routing::get, routing::post, Router, response::IntoResponse, http::HeaderMap};
use mcp_passport::auth::OidcConfig;
use mcp_passport::config::AuthScheme;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn test_sse_piping_flow() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-sse-v3";

    // 1. Setup Mock SSE Server
    use axum::response::sse::{Event, Sse};
    use futures::stream;
    use mcp_passport::crypto::DpopKey;

    let mcp_app = Router::new().route(
        "/sse",
        get(|| async move {
            let stream = stream::iter(vec![Ok::<Event, std::convert::Infallible>(
                Event::default().data("{\"jsonrpc\":\"2.0\",\"method\":\"test/notify\"}"),
            )]);
            Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
        }),
    );
    let mcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mcp_addr = mcp_listener.local_addr()?;
    let sse_url = format!("http://127.0.0.1:{}/sse", mcp_addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(mcp_listener, mcp_app).await;
    });

    // 2. Setup Vault and AuthManager (minimal for SSE)
    let vault = Vault::new(test_svc);
    vault.store_token("sse_user", "valid_token")?;
    let dpop_key = DpopKey::generate();
    vault.store_dpop_key("sse_user", &dpop_key.to_bytes())?;

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: Some("a".into()),
        token_url_override: Some("t".into()),
        par_url_override: Some("p".into()),
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };
    let proxy = Arc::new(Proxy::new(
        "http://unused",
        "sse_user",
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    ));

    // 3. Start SSE Listener
    let (stdout_tx, mut stdout_rx) = mpsc::channel::<String>(100);
    let p = proxy.clone();
    let s_url = sse_url.clone();
    tokio::spawn(async move {
        let _ = p.listen_sse(&s_url, stdout_tx).await;
    });

    // 4. Verify SSE data received
    let msg = timeout(Duration::from_secs(5), stdout_rx.recv())
        .await?
        .context("No SSE message")?;
    assert!(msg.contains("test/notify"));

    Ok(())
}

#[tokio::test]
async fn test_reauth_loop_reset_on_failure() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-loop-v4";
    let _ = Vault::new(test_svc).delete_token("loop_user");

    // Mock server that returns 401 only if NO token is provided, 
    // to avoid infinite retry loop during test.
    let mcp_app = Router::new()
        .route("/rpc", post(|headers: HeaderMap| async move {
            let auth = headers.get("Authorization");
            if auth.is_some() {
                // If we get here, it means re-auth happened (or was attempted) 
                // and we are retrying. Return a different error to break the loop.
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Loop broken").into_response();
            }

            let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("127.0.0.1");
            let base = format!("http://{}", host);
            // Point to an invalid discovery URL that will cause AuthManager::discover to fail
            let challenge = format!("Bearer resource_metadata=\"{}/invalid-discovery\"", base);
            (axum::http::StatusCode::UNAUTHORIZED, [("WWW-Authenticate", challenge)], "Unauthorized").into_response()
        }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());
    
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy = Arc::new(Proxy::new(
        &rpc_url,
        "loop_user",
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    ));

    // First attempt should fail because discovery fails (404 on /invalid-discovery)
    let res1 = timeout(Duration::from_secs(5), proxy.clone().handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"}))).await?;
    assert!(res1.is_err());
    let err1_msg = format!("{:?}", res1.err().unwrap());
    assert!(err1_msg.contains("Failed to fetch discovery document") || err1_msg.contains("404"));

    // Second attempt should ALSO fail with same error (Discovery failure), 
    // NOT with "Authentication loop detected", because we reset last_reauth on failure.
    let res2 = timeout(Duration::from_secs(5), proxy.clone().handle_request(json!({"jsonrpc": "2.0", "id": 2, "method": "test"}))).await?;
    let err2_msg = format!("{:?}", res2.err().unwrap());
    assert!(!err2_msg.contains("Authentication loop detected"), "Should not have triggered loop detection, error was: {}", err2_msg);
    assert!(err2_msg.contains("Failed to fetch discovery document") || err2_msg.contains("404"));

    Ok(())
}

#[tokio::test]
async fn test_discovery_url_construction() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-discovery-v1";
    
    // Mock server that returns 401 with and without resource_metadata
    let mcp_app = Router::new()
        .route("/rpc-with-meta", post(|headers: HeaderMap| async move {
            let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("127.0.0.1");
            let challenge = format!("Bearer resource_metadata=\"http://{}/custom-discovery\"", host);
            (axum::http::StatusCode::UNAUTHORIZED, [("WWW-Authenticate", challenge)], "Unauthorized").into_response()
        }))
        .route("/rpc-no-meta", post(|_headers: HeaderMap| async move {
            (axum::http::StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer scope=\"mcp\"")], "Unauthorized").into_response()
        }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base_url = format!("http://127.0.0.1:{}", addr.port());
    
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    // Case 1: resource_metadata is present in header
    let proxy1 = Arc::new(Proxy::new(
        &format!("{}/rpc-with-meta", base_url),
        "user1",
        oidc_config.clone(),
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    ));
    let res1 = timeout(Duration::from_secs(2), proxy1.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"}))).await?;
    let err1 = format!("{:?}", res1.err().unwrap());
    // Should try to fetch from /custom-discovery
    assert!(err1.contains("custom-discovery"));

    // Case 2: resource_metadata is missing, should fallback to root well-known
    let proxy2 = Arc::new(Proxy::new(
        &format!("{}/rpc-no-meta", base_url),
        "user2",
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    ));
    let res2 = timeout(Duration::from_secs(2), proxy2.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"}))).await?;
    let err2 = format!("{:?}", res2.err().unwrap());
    // Should try to fetch from /.well-known/oauth-protected-resource at ROOT, not appended to /rpc-no-meta
    assert!(err2.contains(".well-known/oauth-protected-resource"));
    assert!(!err2.contains("rpc-no-meta/.well-known"));

    Ok(())
}
