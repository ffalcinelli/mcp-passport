use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use mcp_passport::crypto::DpopKey;
use mcp_passport::auth::AuthManager;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::time::Duration;
use tokio::time::timeout;
use testcontainers::{core::WaitFor, runners::AsyncRunner, GenericImage, ImageExt, core::Mount};
use axum::{routing::post, Json, Router};
use axum::http::HeaderMap;
use tracing::info;

async fn mock_mcp_handler(headers: HeaderMap, Json(payload): Json<Value>) -> Json<Value> {
    // Basic DPoP/Authorization check
    let auth = headers.get("Authorization");
    let dpop = headers.get("DPoP");

    if auth.is_none() || dpop.is_none() {
         return Json(json!({
            "jsonrpc": "2.0",
            "id": payload["id"],
            "error": {"code": -32000, "message": "Unauthorized - Missing DPoP/Auth headers"}
        }));
    }

    if payload["method"] == "tools/list" {
        return Json(json!({
            "jsonrpc": "2.0",
            "id": payload["id"],
            "result": {
                "tools": [
                    {"name": "test_tool", "description": "A tool from the test mock"}
                ]
            }
        }));
    }

    Json(json!({
        "jsonrpc": "2.0",
        "id": payload["id"],
        "error": {"code": -32601, "message": "Method not found"}
    }))
}

#[tokio::test]
async fn test_fapi_dpop_proxy_with_testcontainers() -> anyhow::Result<()> {
    // 1. Setup tracing
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .try_init();

    // 2. Start Keycloak using Testcontainers
    let realm_path = std::env::current_dir()?.join("keycloak-realm.json");
    let realm_path_str = realm_path.to_str().unwrap();
    
    let keycloak_img = GenericImage::new("quay.io/keycloak/keycloak", "latest")
        .with_wait_for(WaitFor::message_on_stdout("Listening on:"))
        .with_env_var("KEYCLOAK_ADMIN", "admin")
        .with_env_var("KEYCLOAK_ADMIN_PASSWORD", "admin")
        .with_mount(Mount::bind_mount(realm_path_str, "/opt/keycloak/data/import/realm.json"))
        .with_cmd(["start-dev", "--import-realm"]);

    let keycloak_container = keycloak_img.start().await.expect("Failed to start Keycloak");

    let keycloak_port = keycloak_container.get_host_port_ipv4(8080).await?;
    let keycloak_base = format!("http://127.0.0.1:{}", keycloak_port);
    let oidc_base = format!("{}/realms/mcp/protocol/openid-connect", keycloak_base);
    
    info!("Keycloak started at {}", keycloak_base);

    // 3. Start Mock MCP Server using Axum
    let app = Router::new().route("/rpc", post(mock_mcp_handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mock_addr = listener.local_addr()?;
    let mock_url = format!("http://{}/rpc", mock_addr);
    
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    info!("Mock MCP server started at {}", mock_url);

    // 4. Seed the vault for test_user
    let test_svc = "mcp-passport-keycloak-integration-v2";
    let vault = Vault::new(test_svc);
    vault.store_token("test_user_kc", "test_access_token")?;
    let dpop_key = DpopKey::generate();
    vault.store_dpop_key("test_user_kc", &dpop_key.to_bytes())?;

    // 5. Initialize AuthManager and Proxy
    let auth_manager = Arc::new(AuthManager::discover(
        None,
        "mcp-passport".into(),
        "http://127.0.0.1:8082/callback".into(),
        test_svc,
        Some(format!("{}/auth", oidc_base)),
        Some(format!("{}/token", oidc_base)),
        Some(format!("{}/par", oidc_base)),
    ).await?);

    let proxy = Arc::new(Proxy::new(&mock_url, "test_user_kc", auth_manager, test_svc, "2025-11-25"));
    
    // 6. Mock stdio
    let (mut client_writer, proxy_reader) = io::duplex(1024);
    let (proxy_writer, mut client_reader) = io::duplex(1024);

    let proxy_task = proxy.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(proxy_reader).lines();
        let mut writer = proxy_writer;
        while let Ok(Some(line)) = reader.next_line().await {
            let p = proxy_task.clone();
            if let Ok(payload) = serde_json::from_str::<Value>(&line) {
                match p.handle_request(payload).await {
                    Ok(response) => {
                        let res_line = format!("{}\n", serde_json::to_string(&response).unwrap());
                        let _ = writer.write_all(res_line.as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                    Err(e) => eprintln!("Proxy error: {:?}", e),
                }
            }
        }
    });

    // 7. Execute Request
    let request = json!({
        "jsonrpc": "2.0",
        "id": "123",
        "method": "tools/list",
        "params": {}
    });
    
    client_writer.write_all(format!("{}\n", request).as_bytes()).await?;
    client_writer.flush().await?;

    let mut reader = BufReader::new(&mut client_reader).lines();
    let result = timeout(Duration::from_secs(45), reader.next_line()).await;

    match result {
        Ok(Ok(Some(line))) => {
            let response: Value = serde_json::from_str(&line)?;
            info!("Received response: {:?}", response);
            assert_eq!(response["id"], "123");
            assert!(response["result"]["tools"].is_array());
            assert_eq!(response["result"]["tools"][0]["name"], "test_tool");
        }
        _ => anyhow::bail!("Integration test failed or timed out"),
    }

    Ok(())
}
