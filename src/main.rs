use mcp_passport::config::Config;
use mcp_passport::proxy::Proxy;
use mcp_passport::auth::AuthManager;
use mcp_passport::Result;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, error};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse configuration from CLI and Environment Variables
    let config = Config::parse();

    // Ensure logs directory exists
    std::fs::create_dir_all("logs")?;

    // Setup logging to file (rotating daily)
    let file_appender = tracing_appender::rolling::daily("logs", "mcp-passport.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    // Initialize tracing with dual outputs: stderr (for human/client) and file (for debugging)
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(fmt::layer().with_ansi(false).with_writer(non_blocking))
        .init();

    info!("mcp-passport starting up...");
    info!("Configuration: {:?}", config);

    let (stdout_tx, mut stdout_rx) = mpsc::channel::<String>(100);

    // Dedicated stdout writer task
    let stdout_handle = tokio::spawn(async move {
        let mut stdout = io::stdout();
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

    let auth_manager = Arc::new(AuthManager::discover(
        config.oidc_discovery_url.as_deref(),
        config.oidc_client_id.clone(),
        config.oidc_redirect_url.clone(),
        "mcp-passport",
        config.kc_auth_url.clone(),
        config.kc_token_url.clone(),
        config.kc_par_url.clone(),
    ).await?);

    let proxy = Arc::new(Proxy::new(
        &config.remote_mcp_url,
        &config.user_id,
        auth_manager,
        "mcp-passport",
        &config.mcp_protocol_version,
    ));
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
    let stdin = io::stdin();
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
                            match serde_json::from_str::<serde_json::Value>(&line) {
                                Ok(payload) => {
                                    let has_id = payload.get("id").is_some();
                                    match proxy_task.handle_request(payload).await {
                                        Ok(response) => {
                                            if has_id {
                                                if let Ok(res_str) = serde_json::to_string(&response) {
                                                    let _ = task_stdout_tx.send(res_str).await;
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
