mod common;

use axum::http::HeaderMap;
use axum::{routing::post, Json, Router};
use mcp_passport::auth::OidcConfig;
use mcp_passport::config::AuthScheme;
use mcp_passport::crypto::DpopKey;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
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
#[ignore]
async fn test_fapi_dpop_proxy_with_testcontainers() -> anyhow::Result<()> {
    // Ensure we use the memory vault and skip browser for reliability in all environments
    std::env::set_var("MCP_PASSPORT_SKIP_OPEN_BROWSER", "1");

    // 1. Setup tracing
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_writer(std::io::stderr)
        .try_init();

    // 2. Start Keycloak using Testcontainers
    let keycloak = common::start_keycloak().await?;
    let keycloak_base = keycloak.base.clone();
    let realm_base = format!("{}/realms/mcp", keycloak_base);
    let oidc_base = format!("{}/protocol/openid-connect", realm_base);

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
    let test_svc = "mcp-passport-keycloak-integration-v10";
    let vault = Vault::in_memory(test_svc);
    vault.store_token("test_user_kc", "test_access_token")?;
    let dpop_key = DpopKey::generate();
    vault.store_dpop_key("test_user_kc", &dpop_key.to_bytes())?;

    // 5. Initialize OidcConfig and Proxy
    let oidc_config = OidcConfig {
        client_id: "mcp-passport".into(),
        redirect_url: "http://127.0.0.1:8082/callback".into(),
        auth_url_override: Some(format!("{}/auth", oidc_base)),
        token_url_override: Some(format!("{}/token", oidc_base)),
        par_url_override: Some(format!("{}/par", oidc_base)),
        ..Default::default()
    };

    let proxy = Proxy::new(
        &mock_url,
        "test_user_kc",
        oidc_config,
        vault.clone(),
        "2025-11-25",
        AuthScheme::Dpop,
    );

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
                match p.call(payload).await {
                    Ok(None) => {}
                    Ok(Some(response)) => {
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

    client_writer
        .write_all(format!("{}\n", request).as_bytes())
        .await?;
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
