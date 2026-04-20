use anyhow::Context;
use axum::http::{HeaderMap, StatusCode};
use axum::{extract as ax_extract, routing::post, Json, Router};
use fantoccini::{ClientBuilder, Locator};
use mcp_passport::auth::OidcConfig;
use mcp_passport::config::AuthScheme;
use mcp_passport::proxy::Proxy;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use testcontainers::{core::Mount, core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::info;

#[derive(Clone)]
struct McpState {
    oidc_discovery: String,
}

async fn mock_mcp_handler(
    ax_extract::State(state): ax_extract::State<McpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> (StatusCode, HeaderMap, Json<Value>) {
    let mut resp_headers = HeaderMap::new();
    let auth = headers.get("Authorization");

    if let Some(auth_str) = auth.and_then(|h| h.to_str().ok()) {
        if auth_str.len() > 20 {
            let res = match payload["method"].as_str() {
                Some("tools/list") => json!({
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "tools": [
                            {"name": "test_tool", "description": "A tool from the test mock"}
                        ]
                    }
                }),
                Some("tools/call") => json!({
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": format!("Echo: {:?}", payload["params"]["arguments"])
                            }
                        ]
                    }
                }),
                _ => json!({
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "error": {"code": -32601, "message": "Method not found"}
                }),
            };
            return (StatusCode::OK, resp_headers, Json(res));
        }
    }

    resp_headers.insert(
        reqwest::header::WWW_AUTHENTICATE,
        format!("Bearer resource_metadata=\"{}\"", state.oidc_discovery)
            .parse()
            .unwrap(),
    );

    (
        StatusCode::UNAUTHORIZED,
        resp_headers,
        Json(json!({"error": "unauthorized"})),
    )
}

#[tokio::test]
async fn test_jdoe_login_and_tool_invocation() -> anyhow::Result<()> {
    // 0. Setup environment and tracing
    std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
    std::env::set_var("MCP_PASSPORT_SKIP_OPEN_BROWSER", "1");

    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .try_init();

    // 1. Start Keycloak
    let realm_path = std::env::current_dir()?.join("keycloak-realm.json");
    let realm_path_str = realm_path.to_str().unwrap();

    let keycloak_img = GenericImage::new("quay.io/keycloak/keycloak", "latest")
        .with_wait_for(WaitFor::message_on_stdout("Listening on:"))
        .with_env_var("KEYCLOAK_ADMIN", "admin")
        .with_env_var("KEYCLOAK_ADMIN_PASSWORD", "admin")
        .with_mount(Mount::bind_mount(
            realm_path_str,
            "/opt/keycloak/data/import/realm.json",
        ))
        .with_cmd(["start-dev", "--import-realm"]);

    let keycloak_container = keycloak_img
        .start()
        .await
        .expect("Failed to start Keycloak");

    let keycloak_port = keycloak_container.get_host_port_ipv4(8080).await?;
    let keycloak_base = format!("http://127.0.0.1:{}", keycloak_port);
    let oidc_discovery = format!(
        "{}/realms/mcp/.well-known/openid-configuration",
        keycloak_base
    );

    info!("Keycloak started at {}", keycloak_base);

    // 2. Start Chromedriver
    let chromedriver_img = GenericImage::new("selenium/standalone-chrome", "latest")
        .with_wait_for(WaitFor::message_on_stdout("Started Selenium Standalone"))
        .with_network("host");
    let _chromedriver_container = chromedriver_img
        .start()
        .await
        .expect("Failed to start Chromedriver");
    let chrome_url = "http://localhost:4444";

    // 3. Start Mock MCP Server
    let mcp_state = McpState {
        oidc_discovery: oidc_discovery.clone(),
    };
    let app = Router::new()
        .route("/rpc", post(mock_mcp_handler))
        .with_state(mcp_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mock_addr = listener.local_addr()?;
    let mock_url = format!("http://{}/rpc", mock_addr);

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    info!("Mock MCP server started at {}", mock_url);

    // 4. Initialize OidcConfig and Proxy
    let user_id = "jdoe";
    let redirect_url = "http://127.0.0.1:8082/callback";

    let oidc_config = OidcConfig {
        discovery_url: Some(oidc_discovery),
        client_id: "mcp-passport".into(),
        redirect_url: redirect_url.to_string(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
        template_dir: None,
    };

    let proxy = Proxy::new(
        &mock_url,
        user_id,
        oidc_config.clone(),
        "mcp-passport-jdoe-test",
        "2025-11-25",
        AuthScheme::Bearer,
    );

    // 5. Setup Auth URL capture
    let (oneshot_tx, oneshot_rx) = oneshot::channel::<String>();

    let proxy_for_auth = proxy.clone();
    tokio::spawn(async move {
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

    // 6. Trigger request
    let proxy_call = proxy.clone();
    let request_task = tokio::spawn(async move {
        proxy_call
            .handle_request(json!({
                "jsonrpc": "2.0",
                "id": "list-1",
                "method": "tools/list",
                "params": {}
            }))
            .await
    });

    // 7. Perform Login
    info!("Waiting for Auth URL...");
    let auth_url = timeout(Duration::from_secs(45), oneshot_rx).await??;
    info!("Logging in via: {}", auth_url);

    let mut caps = serde_json::map::Map::new();
    let chrome_opts = json!({ "args": ["--headless", "--disable-gpu", "--no-sandbox"] });
    caps.insert("goog:chromeOptions".to_string(), chrome_opts);

    let client = ClientBuilder::native()
        .capabilities(caps)
        .connect(&chrome_url)
        .await?;
    client.goto(&auth_url).await?;

    info!("Submitting credentials for jdoe...");
    timeout(
        Duration::from_secs(30),
        client.wait().for_element(Locator::Id("username")),
    )
    .await??;
    client
        .find(Locator::Id("username"))
        .await?
        .send_keys("jdoe")
        .await?;
    client
        .find(Locator::Id("password"))
        .await?
        .send_keys("password")
        .await?;
    client.find(Locator::Id("kc-login")).await?.click().await?;

    // 8. Verify request success
    info!("Waiting for first request to complete...");
    let res = timeout(Duration::from_secs(90), request_task).await??;
    info!("Request result: {:?}", res);
    let val = res.context("Request failed")?;
    assert!(val.get("result").is_some(), "Result missing in response");

    // 9. Invoke a tool
    info!("Invoking mock tool...");
    let res_tool = proxy
        .handle_request(json!({
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {
                "name": "test_tool",
                "arguments": { "input": "hello" }
            }
        }))
        .await?;

    info!("Tool call result: {:?}", res_tool);
    assert!(res_tool.get("result").is_some());

    client.close().await?;
    Ok(())
}
