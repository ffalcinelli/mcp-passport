pub mod auth;
pub mod config;
pub mod crypto;
pub mod proxy;
pub mod templates;
pub mod vault;

use crate::auth::OidcConfig;
use crate::config::Config;
use crate::proxy::Proxy;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Shared result type for the crate.
pub type Result<T> = anyhow::Result<T>;

pub async fn run<R, W>(config: Config, stdin: R, mut stdout: W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
        template_dir: config.template_dir.clone(),
    };

    let proxy = Proxy::new(
        &config.remote_mcp_url,
        &config.user_id,
        oidc_config,
        "mcp-passport",
        &config.mcp_protocol_version,
        config.auth_scheme,
    );
    let sse_url = config.remote_sse_url.clone();

    // Task 1: Persistent SSE Listener (Server -> Client)
    let sse_proxy = proxy.clone();
    let sse_stdout_tx = stdout_tx.clone();
    let sse_handle = tokio::spawn(async move {
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

async fn process_message(proxy: Arc<Proxy>, line: String, stdout_tx: mpsc::Sender<String>) {
    match serde_json::from_str::<serde_json::Value>(&line) {
        Ok(payload) => {
            let has_id = payload.get("id").is_some();
            match proxy.handle_request(payload).await {
                Ok(response) => {
                    if has_id {
                        if let Ok(res_str) = serde_json::to_string(&response) {
                            let _ = stdout_tx.send(res_str).await;
                        }
                    }
                }
                Err(e) => {
                    error!(error = ?e, "Failed to proxy request to remote server");
                }
            }
        }
        Err(e) => error!("Invalid JSON received on stdio: {:?}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthScheme;
    use crate::vault::Vault;
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
                discovery_url: None,
                client_id: "c".into(),
                redirect_url: "r".into(),
                auth_url_override: None,
                token_url_override: None,
                par_url_override: None,
                internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
                internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
                template_dir: None,
            },
            "svc",
            "v1",
            AuthScheme::Bearer,
        );

        process_message(proxy, "invalid json".to_string(), tx).await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_process_message_no_id() {
        let (tx, mut rx) = mpsc::channel(1);
        let proxy = Proxy::new(
            "http://localhost",
            "user",
            OidcConfig {
                discovery_url: None,
                client_id: "c".into(),
                redirect_url: "r".into(),
                auth_url_override: None,
                token_url_override: None,
                par_url_override: None,
                internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
                internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
                template_dir: None,
            },
            "svc",
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

        let proxy = Proxy::new(
            &rpc_url,
            "user",
            OidcConfig {
                discovery_url: None,
                client_id: "c".into(),
                redirect_url: "r".into(),
                auth_url_override: None,
                token_url_override: None,
                par_url_override: None,
                internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
                internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
                template_dir: None,
            },
            "test_process_message_svc",
            "v1",
            AuthScheme::Bearer,
        );

        // Pre-populate vault to skip OIDC
        let vault = Vault::new("test_process_message_svc");
        std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
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
            remote_sse_url: format!("http://127.0.0.1:{}/sse", addr.port()),
            user_id: "test-user".into(),
            oidc_discovery_url: None,
            oidc_client_id: "client".into(),
            oidc_redirect_url: "http://localhost:1/callback".into(),
            kc_auth_url: Some("http://localhost:1/auth".into()),
            kc_token_url: Some("http://localhost:1/token".into()),
            kc_par_url: Some("http://localhost:1/par".into()),
            log_level: "info".into(),
            log_dir: "/tmp/mcp-passport".into(),
            template_dir: None,
            mcp_protocol_version: "2025-11-25".into(),
            auth_scheme: AuthScheme::Bearer,
        };

        // Pre-populate vault to skip OIDC
        let vault = Vault::new("mcp-passport");
        std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
        vault.store_token("test-user", "valid")?;
        vault.store_dpop_key("test-user", &crate::crypto::DpopKey::generate().to_bytes())?;

        let run_handle =
            tokio::spawn(async move { run(config, server_in_rx, server_out_tx).await });

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
