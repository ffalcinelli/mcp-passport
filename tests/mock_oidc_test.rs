use anyhow::Context;
use axum::{routing::get, Router};
use mcp_passport::auth::OidcConfig;
use mcp_passport::config::AuthScheme;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
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
