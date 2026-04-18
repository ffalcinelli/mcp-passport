use anyhow::Context;
use fantoccini::{ClientBuilder, Locator};
use mcp_passport::auth::OidcConfig;
use mcp_passport::config::AuthScheme;
use mcp_passport::proxy::Proxy;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::info;

/// This test simulates a "real world" scenario where:
/// 1. Docker Compose is running (Keycloak + Mock MCP Server)
/// 2. mcp-passport is started
/// 3. An agent sends a request
/// 4. mcp-passport triggers OIDC flow
/// 5. We automate the login via Selenium/Fantoccini
/// 6. We verify the request succeeds
/// 7. We send a SECOND request and verify it's INSTANT (no re-auth)
#[tokio::test]
#[ignore] // Requires docker-compose and chromedriver running
async fn test_agent_simulation_with_docker() -> anyhow::Result<()> {
    // 0. Ensure we are using the memory vault for consistent test behavior
    std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
    std::env::set_var("MCP_PASSPORT_SKIP_OPEN_BROWSER", "1");

    let user_id = "agent_test_user";
    let redirect_url = "http://127.0.0.1:8082/callback";

    let oidc_config = OidcConfig {
        discovery_url: Some(
            "http://localhost:8080/realms/mcp/.well-known/openid-configuration".to_string(),
        ),
        client_id: "mcp-passport".to_string(),
        redirect_url: redirect_url.to_string(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy = Proxy::new(
        "http://localhost:8081/rpc",
        user_id,
        oidc_config.clone(),
        "mcp-passport-integration",
        "2025-11-25",
        AuthScheme::Bearer,
    );

    // 1. Start a listener for the Auth URL
    let (oneshot_tx, oneshot_rx) = oneshot::channel::<String>();

    // We need to inject the URL into our listener
    let proxy_for_auth = proxy.clone();
    tokio::spawn(async move {
        let (tx, rx) = oneshot::channel();
        // Wait for discovery to complete
        loop {
            let am_lock = proxy_for_auth.auth_manager.read().await;
            if let Some(am) = am_lock.as_ref() {
                am.set_internal_url_tx(tx).await;
                break;
            }
            drop(am_lock);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if let Ok(url) = rx.await {
            let _ = oneshot_tx.send(url);
        }
    });

    // 2. Trigger first request (will require auth)
    let proxy_call = proxy.clone();
    let first_request = tokio::spawn(async move {
        proxy_call
            .handle_request(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }))
            .await
    });

    // 3. Wait for the Auth URL and perform headless login
    info!("Waiting for Auth URL...");
    let auth_url = timeout(Duration::from_secs(10), oneshot_rx).await??;
    info!("Login URL received: {}", auth_url);

    let mut caps = serde_json::map::Map::new();
    let chrome_opts = json!({ "args": ["--headless", "--disable-gpu", "--no-sandbox"] });
    caps.insert("goog:chromeOptions".to_string(), chrome_opts);

    let c = ClientBuilder::native()
        .capabilities(caps)
        .connect("http://localhost:9515")
        .await
        .context("Failed to connect to WebDriver (is chromedriver --port=9515 running?)")?;

    c.goto(&auth_url).await?;

    // Keycloak login form
    info!("Filling Keycloak login form...");
    c.find(Locator::Id("username"))
        .await?
        .send_keys("test_user")
        .await?;
    c.find(Locator::Id("password"))
        .await?
        .send_keys("test_password")
        .await?;
    c.find(Locator::Id("kc-login")).await?.click().await?;

    // 4. Verify first request completes
    let res1 = timeout(Duration::from_secs(30), first_request).await??;
    assert!(res1.is_ok(), "First request failed: {:?}", res1.err());
    info!("First request successful!");

    // 5. Trigger SECOND request (should be INSTANT, no auth triggered)
    info!("Starting second request (should use cached token)...");
    let start = std::time::Instant::now();
    let res2 = timeout(
        Duration::from_secs(2),
        proxy.clone().handle_request(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })),
    )
    .await??;

    let duration = start.elapsed();
    info!("Second request completed in {:?}", duration);
    assert!(res2.get("result").is_some());
    assert!(
        duration < Duration::from_millis(500),
        "Second request took too long ({:?}), likely triggered re-auth",
        duration
    );

    c.close().await?;
    Ok(())
}
