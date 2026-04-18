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
            return (
                StatusCode::OK,
                resp_headers,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "tools": [
                            {"name": "test_tool", "description": "A tool from the test mock"}
                        ]
                    }
                })),
            );
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
async fn test_agent_simulation_with_docker() -> anyhow::Result<()> {
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
    let oidc_discovery = format!("{}/realms/mcp/.well-known/openid-configuration", keycloak_base);

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
    let user_id = "agent_test_user";
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
    };

    let proxy = Proxy::new(
        &mock_url,
        user_id,
        oidc_config.clone(),
        "mcp-passport-agent-simulation",
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

    // 6. Trigger first request (will require auth)
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

    // 7. Perform Login
    info!("Waiting for Auth URL...");
    let auth_url = timeout(Duration::from_secs(45), oneshot_rx).await??;
    info!("Login URL received: {}", auth_url);

    let mut caps = serde_json::map::Map::new();
    let chrome_opts = json!({ "args": ["--headless", "--disable-gpu", "--no-sandbox"] });
    caps.insert("goog:chromeOptions".to_string(), chrome_opts);

    let client = ClientBuilder::native()
        .capabilities(caps)
        .connect(&chrome_url)
        .await?;
    client.goto(&auth_url).await?;

    info!("Filling Keycloak login form...");
    timeout(Duration::from_secs(30), client.wait().for_element(Locator::Id("username"))).await??;
    client.find(Locator::Id("username"))
        .await?
        .send_keys("jdoe")
        .await?;
    client.find(Locator::Id("password"))
        .await?
        .send_keys("password")
        .await?;
    client.find(Locator::Id("kc-login")).await?.click().await?;

    // 8. Verify first request completes
    info!("Waiting for first request to complete...");
    let res1 = timeout(Duration::from_secs(90), first_request).await??;
    assert!(res1.is_ok(), "First request failed: {:?}", res1.err());
    info!("First request successful!");

    // 9. Trigger SECOND request (should be INSTANT, no auth triggered)
    info!("Starting second request (should use cached token)...");
    let start = std::time::Instant::now();
    let res2 = timeout(
        Duration::from_secs(5),
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
        duration < Duration::from_millis(2000), // Slightly relaxed for CI overhead but still ensures no re-auth
        "Second request took too long ({:?}), likely triggered re-auth",
        duration
    );

    client.close().await?;
    Ok(())
}
