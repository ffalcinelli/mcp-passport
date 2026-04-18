use anyhow::Context;
use fantoccini::{ClientBuilder, Locator};
use mcp_passport::auth::OidcConfig;
use mcp_passport::config::{AuthScheme, Config};
use mcp_passport::proxy::Proxy;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tracing::{info, warn};

#[tokio::test]
#[ignore] // Requires docker-compose and chromedriver running
async fn test_jdoe_login_and_tool_invocation() -> anyhow::Result<()> {
    // 0. Setup test environment
    std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
    std::env::set_var("MCP_PASSPORT_SKIP_OPEN_BROWSER", "1");

    let user_id = "jdoe";
    let redirect_url = "http://127.0.0.1:8082/callback";

    let oidc_config = OidcConfig {
        discovery_url: Some("http://localhost:8080/realms/mcp/.well-known/openid-configuration".to_string()),
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
        "mcp-passport-jdoe-test",
        "2025-11-25",
        AuthScheme::Bearer,
    );

    // 1. Setup Auth URL capture
    let (url_tx, mut url_rx) = mpsc::channel::<String>(1);
    let (oneshot_tx, oneshot_rx) = oneshot::channel::<String>();
    
    let proxy_for_auth = proxy.clone();
    tokio::spawn(async move {
        // We need to wait for AuthManager to be discovered
        loop {
            let am_lock = proxy_for_auth.auth_manager.read().await;
            if let Some(am) = am_lock.as_ref() {
                let (tx, rx) = oneshot::channel();
                am.set_internal_url_tx(tx).await;
                if let Ok(url) = rx.await {
                    let _ = oneshot_tx.send(url);
                }
                break;
            }
            drop(am_lock);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    // 2. Trigger request
    let proxy_call = proxy.clone();
    let request_task = tokio::spawn(async move {
        proxy_call.handle_request(json!({
            "jsonrpc": "2.0",
            "id": "list-1",
            "method": "tools/list",
            "params": {}
        })).await
    });

    // 3. Perform Login
    info!("Waiting for Auth URL...");
    let auth_url = timeout(Duration::from_secs(15), oneshot_rx).await??;
    info!("Logging in via: {}", auth_url);

    let mut caps = serde_json::map::Map::new();
    let chrome_opts = json!({ "args": ["--headless", "--disable-gpu", "--no-sandbox"] });
    caps.insert("goog:chromeOptions".to_string(), chrome_opts);
    
    let c = ClientBuilder::native()
        .capabilities(caps)
        .connect("http://localhost:9515")
        .await
        .context("Failed to connect to WebDriver (is chromedriver --port=9515 running?)")?;

    c.goto(&auth_url).await?;
    
    info!("Submitting credentials for jdoe...");
    c.find(Locator::Id("username")).await?.send_keys("jdoe").await?;
    c.find(Locator::Id("password")).await?.send_keys("jdoe_password").await?; // Assuming this is the password in keycloak-realm.json
    c.find(Locator::Id("kc-login")).await?.click().await?;

    // 4. Verify request success
    let res = timeout(Duration::from_secs(30), request_task).await??;
    info!("Request result: {:?}", res);
    let val = res.context("Request failed")?;
    assert!(val.get("result").is_some(), "Result missing in response");

    // 5. Invoke a tool
    info!("Invoking mock tool...");
    let res_tool = proxy.handle_request(json!({
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "test_tool",
            "arguments": { "input": "hello" }
        }
    })).await?;
    
    info!("Tool call result: {:?}", res_tool);
    assert!(res_tool.get("result").is_some());

    c.close().await?;
    Ok(())
}
