use mcp_passport::proxy::Proxy;
use mcp_passport::auth::AuthManager;
use mcp_passport::vault::Vault;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::time::Duration;
use tokio::time::timeout;
use ax_extract::Form;
use axum::{routing::{post, get}, Json, Router, extract as ax_extract};
use axum::http::{HeaderMap, StatusCode};
use tokio::sync::{oneshot, mpsc};
use anyhow::Context;

async fn mock_mcp_handler(headers: HeaderMap, Json(payload): Json<Value>) -> (StatusCode, Json<Value>) {
    let auth = headers.get("Authorization");
    if let Some(auth_str) = auth.and_then(|h| h.to_str().ok()) {
        if auth_str.contains("valid_mock_token") {
            return (StatusCode::OK, Json(json!({
                "jsonrpc": "2.0",
                "id": payload["id"],
                "result": {"status": "ok"}
            })));
        }
    }
    
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})))
}

#[tokio::test]
async fn test_mock_oidc_reauth_flow() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-reauth-v2";

    // 1. Setup State Capture Channel for PAR
    let (state_tx, mut state_rx) = mpsc::channel::<String>(1);
    let state_tx = Arc::new(tokio::sync::Mutex::new(state_tx));

    // 2. Setup Mock MCP Server
    let mcp_app = Router::new().route("/rpc", post(mock_mcp_handler));
    let mcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mcp_addr = mcp_listener.local_addr()?;
    let mcp_url = format!("http://{}/rpc", mcp_addr);
    let _mcp_url_clone = mcp_url.clone();
    tokio::spawn(async move { 
        let _ = axum::serve(mcp_listener, mcp_app).await; 
    });

    // 3. Setup Mock OIDC Server
    let oidc_app = Router::new()
        .route("/par", post(move |Form(params): Form<Value>| {
            let stx = state_tx.clone();
            async move {
                if let Some(state) = params.get("state").and_then(|s| s.as_str()) {
                    let _ = stx.lock().await.send(state.to_string()).await;
                }
                Json(json!({"request_uri": "urn:ietf:params:oauth:request_uri:123", "expires_in": 60}))
            }
        }))
        .route("/token", post(|headers: HeaderMap, Form(_params): Form<Value>| async move {
            let dpop = headers.get("DPoP");
            if dpop.is_none() {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing dpop"})));
            }
            (StatusCode::OK, Json(json!({"access_token": "valid_mock_token", "token_type": "DPoP", "expires_in": 3600})))
        }));

    let oidc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let oidc_addr = oidc_listener.local_addr()?;
    let oidc_url = format!("http://{}", oidc_addr);
    let _oidc_url_clone = oidc_url.clone();
    tokio::spawn(async move { 
        let _ = axum::serve(oidc_listener, oidc_app).await; 
    });

    // 4. Initialize AuthManager
    let auth_manager = Arc::new(AuthManager::discover(
        None,
        "test-client".into(),
        "http://127.0.0.1:0/callback".into(),
        test_svc,
        Some(format!("{}/auth", oidc_url)),
        Some(format!("{}/token", oidc_url)),
        Some(format!("{}/par", oidc_url)),
    ).await?);

    // 5. Initialize Proxy (Ensure clean state)
    let vault = Vault::new(test_svc);
    let _ = vault.delete_token("mock_user");
    
    let proxy = Arc::new(Proxy::new(&mcp_url, "mock_user", auth_manager.clone(), test_svc, "2025-11-25"));

    // 6. Setup URL capture from AuthManager
    let (url_tx, url_rx) = oneshot::channel::<String>();
    auth_manager.set_internal_url_tx(url_tx).await;
    let (addr_tx, addr_rx) = oneshot::channel::<std::net::SocketAddr>();
    auth_manager.set_internal_callback_tx(addr_tx).await;

    // 7. Start Proxy Task
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

    // 8. Execute Request (triggers reauth)
    client_writer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"ping\"}\n").await?;
    client_writer.flush().await?;

    // 9. Capture Auth URL and state from Mock OIDC
    let _auth_url_str = timeout(Duration::from_secs(5), url_rx).await??;
    let expected_state = timeout(Duration::from_secs(5), state_rx.recv()).await?.context("Failed to get state from PAR")?;
    let bound_addr = timeout(Duration::from_secs(5), addr_rx).await??;
    
    // 10. Simulate Browser Callback
    let client = reqwest::Client::new();
    let callback_res = client.get(format!("http://{}/callback", bound_addr))
        .query(&[("code", "mock_code"), ("state", &expected_state)])
        .send().await?;
    
    assert_eq!(callback_res.status(), StatusCode::OK);

    // 11. Read final response from Proxy
    let mut reader = BufReader::new(&mut client_reader).lines();
    let res_line = timeout(Duration::from_secs(5), reader.next_line()).await??.context("Failed to read response")?;
    let response: Value = serde_json::from_str(&res_line)?;
    
    assert_eq!(response["result"]["status"], "ok");

    Ok(())
}

#[tokio::test]
async fn test_sse_piping_flow() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-sse-v2";

    // 1. Setup Mock SSE Server
    use axum::response::sse::{Event, Sse};
    use futures::stream;
    use mcp_passport::crypto::DpopKey;
    
    let mcp_app = Router::new().route("/sse", get(|| async move {
        let stream = stream::iter(vec![
            Ok::<Event, std::convert::Infallible>(Event::default().data("{\"jsonrpc\":\"2.0\",\"method\":\"test/notify\"}")),
        ]);
        Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
    }));
    let mcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mcp_addr = mcp_listener.local_addr()?;
    let sse_url = format!("http://{}/sse", mcp_addr);
    tokio::spawn(async move { let _ = axum::serve(mcp_listener, mcp_app).await; });

    // 2. Setup Vault and AuthManager (minimal for SSE)
    let vault = Vault::new(test_svc);
    vault.store_token("sse_user", "valid_token")?;
    let dpop_key = DpopKey::generate();
    vault.store_dpop_key("sse_user", &dpop_key.to_bytes())?;

    let auth_manager = Arc::new(AuthManager::discover(None, "c".into(), "r".into(), test_svc, Some("a".into()), Some("t".into()), Some("p".into())).await?);
    let proxy = Arc::new(Proxy::new("http://unused", "sse_user", auth_manager, test_svc, "2025-11-25"));

    // 3. Start SSE Listener
    let (stdout_tx, mut stdout_rx) = mpsc::channel::<String>(100);
    let p = proxy.clone();
    let s_url = sse_url.clone();
    tokio::spawn(async move {
        let _ = p.listen_sse(&s_url, stdout_tx).await;
    });

    // 4. Verify SSE data received
    let msg = timeout(Duration::from_secs(5), stdout_rx.recv()).await?.context("No SSE message")?;
    assert!(msg.contains("test/notify"));

    Ok(())
}
