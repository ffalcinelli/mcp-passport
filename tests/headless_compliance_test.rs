use mcp_passport::proxy::Proxy;
use mcp_passport::auth::OidcConfig;
use mcp_passport::vault::Vault;
use mcp_passport::config::AuthScheme;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::time::Duration;
use tokio::time::timeout;
use ax_extract::Form;
use axum::{routing::{post, get}, Json, Router, extract as ax_extract, extract::Query};
use axum::http::{HeaderMap, StatusCode};
use tokio::sync::{oneshot, mpsc};
use anyhow::Context;
use tracing::{info, error};
use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt};
use fantoccini::{ClientBuilder, Locator};

#[derive(Clone)]
struct McpState {
    metadata_url: String,
}

async fn mock_mcp_handler(
    ax_extract::State(state): ax_extract::State<McpState>,
    headers: HeaderMap,
    Json(payload): Json<Value>
) -> (StatusCode, HeaderMap, Json<Value>) {
    let mut resp_headers = HeaderMap::new();
    let auth = headers.get("Authorization");
    if let Some(auth_str) = auth.and_then(|h| h.to_str().ok()) {
        if auth_str.contains("valid_mock_token") {
            return (StatusCode::OK, resp_headers, Json(json!({
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"status": "ok"}
            })));
        }
    }
    
    resp_headers.insert(
        reqwest::header::WWW_AUTHENTICATE,
        format!("Bearer resource_metadata=\"{}\"", state.metadata_url).parse().unwrap()
    );
    (StatusCode::UNAUTHORIZED, resp_headers, Json(json!({"error": "unauthorized"})))
}

use std::collections::HashMap;
use tokio::sync::Mutex as TokioMutex;

#[derive(Clone)]
struct OidcState {
    sessions: Arc<TokioMutex<HashMap<String, String>>>,
    state_tx: Arc<TokioMutex<mpsc::Sender<String>>>,
}

#[tokio::test]
async fn test_full_compliance_flow_headless() -> anyhow::Result<()> {
    // 0. Setup tracing
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .try_init();

    // 1. Start Chromedriver
    let chromedriver_img = GenericImage::new("selenium/standalone-chrome", "latest")
        .with_wait_for(WaitFor::message_on_stdout("Started Selenium Standalone"))
        .with_network("host");
    let _chromedriver_container = chromedriver_img.start().await.expect("Failed to start Chromedriver");
    let chrome_url = "http://localhost:4444";

    // 2. Setup Mock OIDC Server with UI and session tracking
    let (state_tx, mut _state_rx) = mpsc::channel::<String>(1);
    let sessions = Arc::new(TokioMutex::new(HashMap::<String, String>::new()));
    
    let oidc_state = OidcState {
        sessions,
        state_tx: Arc::new(TokioMutex::new(state_tx)),
    };

    let oidc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let oidc_addr = oidc_listener.local_addr()?;
    let oidc_url = format!("http://127.0.0.1:{}", oidc_addr.port());
    let oidc_url_for_mcp = oidc_url.clone();
    let oidc_url_for_discovery = oidc_url.clone();

    let oidc_app = Router::new()
        .route("/discovery", get(move || {
            let base = oidc_url_for_discovery.clone();
            async move {
                Json(json!({
                    "authorization_endpoint": format!("{}/auth", base),
                    "token_endpoint": format!("{}/token", base),
                    "pushed_authorization_request_endpoint": format!("{}/par", base)
                }))
            }
        }))
        .route("/par", post(|ax_extract::State(state): ax_extract::State<OidcState>, Form(params): Form<Value>| async move {
            if params.get("resource").is_none() {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing_resource"})));
            }
            let req_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
            if let Some(s) = params.get("state").and_then(|v| v.as_str()) {
                state.sessions.lock().await.insert(req_uri.clone(), s.to_string());
                let _ = state.state_tx.lock().await.send(s.to_string()).await;
            }
            (StatusCode::OK, Json(json!({"request_uri": req_uri, "expires_in": 60})))
        }))
        .route("/auth", get(|ax_extract::State(state): ax_extract::State<OidcState>, Query(params): Query<Value>| async move {
            let req_uri = params.get("request_uri").and_then(|v| v.as_str()).unwrap_or("");
            let session_state = {
                let lock = state.sessions.lock().await;
                lock.get(req_uri).cloned().unwrap_or_default()
            };
            
            let code = "mock_code";
            let redirect_uri = "http://localhost:8082/callback"; 
            
            axum::response::Html(format!(
                "<html><body><form action='{}' method='GET'>
                <input type='text' id='username' name='username' value='jdoe'>
                <input type='hidden' name='code' value='{}'>
                <input type='hidden' name='state' value='{}'>
                <button id='login' type='submit'>Login</button>
                </form></body></html>",
                redirect_uri, code, session_state
            ))
        }))
        .route("/token", post(|headers: HeaderMap, Form(params): Form<Value>| async move {
            let dpop = headers.get("DPoP");
            if dpop.is_none() || params.get("resource").is_none() {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_request"})));
            }
            (StatusCode::OK, Json(json!({"access_token": "valid_mock_token", "token_type": "DPoP", "expires_in": 3600})))
        }))
        .with_state(oidc_state);

    tokio::spawn(async move { let _ = axum::serve(oidc_listener, oidc_app).await; });

    // 3. Setup Mock MCP Server
    let mcp_app = Router::new()
        .route("/rpc", post(mock_mcp_handler))
        .with_state(McpState { metadata_url: format!("{}/discovery", oidc_url_for_mcp) });

    let mcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mcp_addr = mcp_listener.local_addr()?;
    let mcp_url = format!("http://127.0.0.1:{}/rpc", mcp_addr.port());
    tokio::spawn(async move { let _ = axum::serve(mcp_listener, mcp_app).await; });

    // 4. Initialize OidcConfig with test channels
    let (url_tx, url_rx) = oneshot::channel::<String>();
    let oidc_config = OidcConfig {
        discovery_url: None, 
        client_id: "test-client".into(),
        redirect_url: "http://localhost:8082/callback".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(Some(url_tx))),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    // 5. Initialize Proxy
    let test_svc = "mcp-passport-compliance-headless-v1";
    let vault = Vault::new(test_svc);
    let _ = vault.delete_token("mock_user");
    let proxy = Arc::new(Proxy::new(&mcp_url, "mock_user", oidc_config, test_svc, "2025-11-25", AuthScheme::Bearer));

    // 6. Start Proxy Task
    let (mut client_writer, proxy_reader) = io::duplex(1024);
    let (proxy_writer, mut client_reader) = io::duplex(1024);
    let p = proxy.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(proxy_reader).lines();
        let mut writer = proxy_writer;
        while let Ok(Some(line)) = reader.next_line().await {
            if let Ok(payload) = serde_json::from_str::<Value>(&line) {
                if let Ok(res) = p.clone().handle_request(payload).await {
                    let _ = writer.write_all(format!("{}\n", res).as_bytes()).await;
                    let _ = writer.flush().await;
                }
            }
        }
    });

    // 7. Execute Request
    client_writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"ping\"}\n").await?;
    client_writer.flush().await?;

    // 8. Headless Browser Automation
    let auth_url = timeout(Duration::from_secs(30), url_rx).await??;
    info!("Headless browser navigating to: {}", auth_url);

    let mut caps = serde_json::map::Map::new();
    let chrome_opts = json!({ "args": ["--headless", "--disable-gpu", "--no-sandbox"] });
    caps.insert("goog:chromeOptions".to_string(), chrome_opts);

    let client = ClientBuilder::native().capabilities(caps).connect(&chrome_url).await?;
    client.goto(&auth_url).await?;
    
    // Wait for our mock UI form and click Login
    client.wait().for_element(Locator::Id("username")).await?;
    info!("Headless browser filling mock form...");
    client.find(Locator::Id("username")).await?.send_keys("jdoe").await?;
    client.find(Locator::Id("login")).await?.click().await?;
    
    // Wait for the redirect to happen (our loopback will handle it)
    info!("Headless browser waiting for success message...");
    match timeout(Duration::from_secs(30), client.wait().for_element(Locator::XPath("//*[contains(text(), 'Authentication successful')]"))).await {
        Ok(_) => info!("Headless browser login completed."),
        Err(_) => {
            let cur = client.current_url().await?;
            let src = client.source().await?;
            error!("Timed out waiting for success. Current URL: {}. Source snippet: {}", cur, &src[..src.len().min(500)]);
            panic!("Timeout waiting for success message");
        }
    }
    client.close().await?;

    // 9. Read final response
    let mut reader = BufReader::new(&mut client_reader).lines();
    let res_line = timeout(Duration::from_secs(30), reader.next_line()).await??.context("Failed to read response")?;
    let response: Value = serde_json::from_str(&res_line)?;
    assert_eq!(response["result"]["status"], "ok");

    Ok(())
}
