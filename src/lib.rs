pub mod auth;
mod challenge;
pub mod config;
pub mod crypto;
mod discovery;
pub mod logging;
mod net;
pub mod proxy;
pub mod templates;
pub mod vault;

use crate::auth::{OidcConfig, Timeouts};
use crate::config::Config;
use crate::proxy::Proxy;
use crate::vault::Vault;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Shared result type for the crate.
pub type Result<T> = anyhow::Result<T>;

/// Runs the proxy using the vault backend selected by the environment
/// (OS keychain unless `MCP_PASSPORT_USE_MEMORY_VAULT` is set).
pub async fn run<R, W>(config: Config, stdin: R, stdout: W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let vault = Vault::from_env(&vault::service_name_for(&config.remote_mcp_url));
    run_with_vault(config, vault, stdin, stdout).await
}

/// Checks the URL policy before anything is sent over the network.
pub fn validate_config(config: &Config) -> Result<()> {
    let allow = config.allow_insecure_http;
    net::require_secure_url(&config.remote_mcp_url, "--remote-mcp-url", allow)?;
    let optional = [
        (&config.remote_sse_url, "--remote-sse-url"),
        (&config.oidc_discovery_url, "--oidc-discovery-url"),
        (&config.kc_auth_url, "--kc-auth-url"),
        (&config.kc_token_url, "--kc-token-url"),
        (&config.kc_par_url, "--kc-par-url"),
    ];
    for (url, what) in optional {
        if let Some(url) = url {
            net::require_secure_url(url, what, allow)?;
        }
    }
    net::require_loopback_redirect(&config.oidc_redirect_url)?;
    Ok(())
}

/// Runs the proxy with an explicit vault.
pub async fn run_with_vault<R, W>(
    config: Config,
    vault: Vault,
    stdin: R,
    mut stdout: W,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    validate_config(&config)?;

    let (stdout_tx, mut stdout_rx) = mpsc::channel::<String>(100);

    // Dedicated stdout writer task
    let stdout_handle = tokio::spawn(async move {
        while let Some(msg) = stdout_rx.recv().await {
            tracing::debug!(message = %msg, "Writing to stdout");
            let mut line = msg;
            line.push('\n');
            if let Err(e) = stdout.write_all(line.as_bytes()).await {
                error!("Failed to write to stdout: {:?}", e);
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    let oidc_config = OidcConfig {
        discovery_url: config.oidc_discovery_url.clone(),
        client_id: config.oidc_client_id.clone(),
        redirect_url: config.oidc_redirect_url.clone(),
        auth_url_override: config.kc_auth_url.clone(),
        token_url_override: config.kc_token_url.clone(),
        par_url_override: config.kc_par_url.clone(),
        template_dir: config.template_dir.clone(),
        allow_insecure_http: config.allow_insecure_http,
        timeouts: Timeouts {
            auth: std::time::Duration::from_secs(config.auth_timeout_secs),
            ..Default::default()
        },
        ..Default::default()
    };

    let proxy = Proxy::new(
        &config.remote_mcp_url,
        &config.user_id,
        oidc_config,
        vault,
        &config.mcp_protocol_version,
        config.auth_scheme,
    );
    // Streamable HTTP serves the GET stream on the MCP endpoint itself.
    let sse_url = config
        .remote_sse_url
        .clone()
        .unwrap_or_else(|| config.remote_mcp_url.clone());

    // Task 1: Persistent SSE Listener (Server -> Client). It starts after the
    // first successful POST, so the session id (if any) is known.
    let sse_proxy = proxy.clone();
    let sse_stdout_tx = stdout_tx.clone();
    let sse_handle = tokio::spawn(async move {
        sse_proxy.wait_until_connected().await;
        if let Err(e) = sse_proxy.listen_sse(&sse_url, sse_stdout_tx).await {
            error!("SSE listener failed: {:?}", e);
        }
    });

    // Task 2: Stdio Read Loop (Client -> Server)
    let mut reader = BufReader::new(stdin).lines();
    let mut tasks = JoinSet::new();

    info!("Ready to proxy MCP stdio messages...");

    loop {
        tokio::select! {
            line_res = reader.next_line() => {
                match line_res {
                    Ok(Some(line)) => {
                        let proxy_task = proxy.clone();
                        let task_stdout_tx = stdout_tx.clone();
                        tasks.spawn(async move {
                            process_message(proxy_task, line, task_stdout_tx).await;
                        });
                    }
                    Ok(None) => {
                        info!("Stdin closed, shutting down...");
                        break;
                    }
                    Err(e) => {
                        error!("Error reading from stdin: {:?}", e);
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down...");
                break;
            }
            Some(res) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(e) = res {
                    error!("Proxy task failed: {:?}", e);
                }
            }
        }
    }

    // Cleanup: wait for remaining tasks and stop SSE listener
    info!("Waiting for remaining tasks to complete...");
    sse_handle.abort();
    while tasks.join_next().await.is_some() {}

    // Drop stdout_tx so the writer task can finish
    drop(stdout_tx);
    let _ = stdout_handle.await;

    Ok(())
}

/// JSON-RPC 2.0 error codes used by the proxy.
const PARSE_ERROR: i64 = -32700;
const INTERNAL_ERROR: i64 = -32603;

fn jsonrpc_error(id: serde_json::Value, code: i64, message: String) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
    .to_string()
}

async fn process_message(proxy: Arc<Proxy>, line: String, stdout_tx: mpsc::Sender<String>) {
    if line.trim().is_empty() {
        return;
    }
    let payload = match serde_json::from_str::<serde_json::Value>(&line) {
        Ok(payload) => payload,
        Err(e) => {
            error!("Invalid JSON received on stdio: {:?}", e);
            let msg = jsonrpc_error(serde_json::Value::Null, PARSE_ERROR, "Parse error".into());
            let _ = stdout_tx.send(msg).await;
            return;
        }
    };

    // Only requests (method + id) expect a response; notifications and the
    // client's responses to server requests must not get one.
    let request_id = match (payload.get("method"), payload.get("id")) {
        (Some(_), Some(id)) => Some(id.clone()),
        _ => None,
    };

    if let Err(e) = proxy.handle_request(payload, &stdout_tx).await {
        error!(error = ?e, "Failed to proxy request to remote server");
        if let Some(id) = request_id {
            let msg = jsonrpc_error(id, INTERNAL_ERROR, format!("mcp-passport: {e:#}"));
            let _ = stdout_tx.send(msg).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthScheme;
    use axum::{routing::post, Router};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_process_message_invalid_json() {
        let (tx, mut rx) = mpsc::channel(1);
        let proxy = Proxy::new(
            "http://localhost",
            "user",
            OidcConfig {
                client_id: "c".into(),
                redirect_url: "r".into(),
                timeouts: crate::auth::Timeouts::fast(),
                ..Default::default()
            },
            Vault::in_memory("svc"),
            "v1",
            AuthScheme::Bearer,
        );

        process_message(proxy, "invalid json".to_string(), tx).await;
        let resp: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(resp["id"], serde_json::Value::Null);
        assert_eq!(resp["error"]["code"], PARSE_ERROR);
    }

    fn proxy_for(url: &str, vault: Vault) -> Arc<Proxy> {
        Proxy::new(
            url,
            "user",
            OidcConfig {
                client_id: "c".into(),
                redirect_url: "r".into(),
                timeouts: crate::auth::Timeouts::fast(),
                ..Default::default()
            },
            vault,
            "v1",
            AuthScheme::Bearer,
        )
    }

    async fn serve_500() -> Result<String> {
        let app = Router::new().route(
            "/rpc",
            post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/rpc", listener.local_addr()?);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(url)
    }

    fn vault_with_credentials() -> Result<Vault> {
        let vault = Vault::in_memory("svc");
        vault.store_token("user", "valid")?;
        vault.store_dpop_key("user", &crate::crypto::DpopKey::generate().to_bytes())?;
        Ok(vault)
    }

    #[test]
    fn test_validate_config() {
        use clap::Parser;
        let parse = |extra: &[&str]| {
            let mut args = vec!["mcp-passport"];
            args.extend_from_slice(extra);
            Config::try_parse_from(args).unwrap()
        };
        assert!(
            validate_config(&parse(&["--remote-mcp-url", "https://mcp.example.com/mcp"])).is_ok()
        );
        assert!(
            validate_config(&parse(&["--remote-mcp-url", "http://127.0.0.1:8081/rpc"])).is_ok()
        );

        let insecure = parse(&["--remote-mcp-url", "http://mcp.example.com/mcp"]);
        assert!(validate_config(&insecure).is_err());
        let allowed = parse(&[
            "--remote-mcp-url",
            "http://mcp.example.com/mcp",
            "--allow-insecure-http",
        ]);
        assert!(validate_config(&allowed).is_ok());

        let bad_override = parse(&[
            "--remote-mcp-url",
            "https://mcp.example.com/mcp",
            "--kc-token-url",
            "http://as.example.com/token",
        ]);
        assert!(validate_config(&bad_override).is_err());

        let bad_redirect = parse(&[
            "--remote-mcp-url",
            "https://mcp.example.com/mcp",
            "--oidc-redirect-url",
            "http://0.0.0.0:8082/callback",
        ]);
        assert!(validate_config(&bad_redirect).is_err());
    }

    #[tokio::test]
    async fn test_process_message_failure_becomes_jsonrpc_error() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        let proxy = proxy_for(&serve_500().await?, vault_with_credentials()?);

        process_message(
            proxy,
            json!({"jsonrpc": "2.0", "id": "req-7", "method": "tools/list"}).to_string(),
            tx,
        )
        .await;

        let resp: serde_json::Value = serde_json::from_str(&rx.try_recv()?)?;
        assert_eq!(resp["id"], "req-7");
        assert_eq!(resp["error"]["code"], INTERNAL_ERROR);
        let message = resp["error"]["message"].as_str().unwrap();
        assert!(message.contains("500"), "{message}");
        assert!(message.contains("boom"), "{message}");
        Ok(())
    }

    #[tokio::test]
    async fn test_process_message_client_response_gets_no_error() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        let proxy = proxy_for(&serve_500().await?, vault_with_credentials()?);

        // A response to a server-initiated request has an id but no method.
        process_message(
            proxy,
            json!({"jsonrpc": "2.0", "id": 3, "result": {}}).to_string(),
            tx,
        )
        .await;
        assert!(rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_process_message_ignores_blank_lines() {
        let (tx, mut rx) = mpsc::channel(1);
        let proxy = proxy_for("http://localhost:1/rpc", Vault::in_memory("svc"));
        process_message(proxy, "   ".to_string(), tx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_process_message_no_id() {
        let (tx, mut rx) = mpsc::channel(1);
        let proxy = Proxy::new(
            "http://localhost",
            "user",
            OidcConfig {
                client_id: "c".into(),
                redirect_url: "r".into(),
                timeouts: crate::auth::Timeouts::fast(),
                ..Default::default()
            },
            Vault::in_memory("svc"),
            "v1",
            AuthScheme::Bearer,
        );

        // A notification has no ID, so it shouldn't produce a response to stdout_tx
        process_message(
            proxy,
            json!({"jsonrpc": "2.0", "method": "notify"}).to_string(),
            tx,
        )
        .await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_process_message_with_id() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);

        let mcp_app = Router::new().route(
            "/rpc",
            post(|| async move { axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());
        tokio::spawn(async move {
            let _ = axum::serve(listener, mcp_app).await;
        });

        let vault = Vault::in_memory("test_process_message_svc");
        let proxy = Proxy::new(
            &rpc_url,
            "user",
            OidcConfig {
                client_id: "c".into(),
                redirect_url: "r".into(),
                timeouts: crate::auth::Timeouts::fast(),
                ..Default::default()
            },
            vault.clone(),
            "v1",
            AuthScheme::Bearer,
        );

        // Pre-populate vault to skip OIDC
        vault.store_token("user", "valid")?;
        vault.store_dpop_key("user", &crate::crypto::DpopKey::generate().to_bytes())?;

        // A message with an ID should produce a response to stdout_tx
        process_message(
            proxy,
            json!({"jsonrpc": "2.0", "id": 1, "method": "test"}).to_string(),
            tx,
        )
        .await;

        let resp = rx.recv().await.expect("Expected a response");
        assert!(resp.contains("\"result\":\"ok\""));
        Ok(())
    }

    #[tokio::test]
    async fn test_run_minimal() -> Result<()> {
        let (mut client_out_rx, server_out_tx) = tokio::io::duplex(1024);
        let (mut client_in_tx, server_in_rx) = tokio::io::duplex(1024);

        let mcp_app = Router::new().route(
            "/rpc",
            post(|| async move { axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());
        tokio::spawn(async move {
            let _ = axum::serve(listener, mcp_app).await;
        });

        let config = Config {
            remote_mcp_url: rpc_url,
            remote_sse_url: Some(format!("http://127.0.0.1:{}/sse", addr.port())),
            user_id: "test-user".into(),
            oidc_discovery_url: None,
            oidc_client_id: "client".into(),
            oidc_redirect_url: "http://localhost:1/callback".into(),
            kc_auth_url: Some("http://localhost:1/auth".into()),
            kc_token_url: Some("http://localhost:1/token".into()),
            kc_par_url: Some("http://localhost:1/par".into()),
            log_level: "info".into(),
            log_dir: None,
            allow_insecure_http: false,
            template_dir: None,
            mcp_protocol_version: "2025-11-25".into(),
            auth_scheme: AuthScheme::Bearer,
            auth_timeout_secs: 300,
        };

        // Pre-populate vault to skip OIDC
        let vault = Vault::in_memory("mcp-passport");
        vault.store_token("test-user", "valid")?;
        vault.store_dpop_key("test-user", &crate::crypto::DpopKey::generate().to_bytes())?;

        let run_handle = tokio::spawn(async move {
            run_with_vault(config, vault, server_in_rx, server_out_tx).await
        });

        // Send a message
        client_in_tx
            .write_all(b"{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"test\"}\n")
            .await?;

        // Wait for response
        let mut buf = [0u8; 1024];
        let n = client_out_rx.read(&mut buf).await?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("\"result\":\"ok\""));

        // Send another message
        client_in_tx
            .write_all(b"{\"jsonrpc\": \"2.0\", \"id\": 2, \"method\": \"test2\"}\n")
            .await?;
        let n = client_out_rx.read(&mut buf).await?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("\"result\":\"ok\""));

        // Close stdin to trigger shutdown
        drop(client_in_tx);

        let res = tokio::time::timeout(std::time::Duration::from_secs(2), run_handle).await??;
        assert!(res.is_ok());
        Ok(())
    }
}
