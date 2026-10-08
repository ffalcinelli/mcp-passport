//! # mcp-passport
//!
//! A local **stdio ⇄ Streamable HTTP bridge** for the [Model Context
//! Protocol](https://modelcontextprotocol.io). It lets AI clients that launch
//! local MCP servers talk to remote, OAuth-protected MCP servers, with FAPI 2.0
//! security: Pushed Authorization Requests, PKCE and DPoP-bound tokens.
//!
//! Most people use the `mcp-passport` binary (see the
//! [README](https://github.com/ffalcinelli/mcp-passport#readme) and the
//! [setup guide](https://github.com/ffalcinelli/mcp-passport/blob/main/GUIDE.md)).
//! This crate exposes the same machinery as a library.
//!
//! ## How it works
//!
//! 1. Each JSON-RPC message read from stdin is POSTed to the MCP server, with
//!    the headers of its protocol era. Modern (2026-07-28) messages carry
//!    `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*`;
//!    legacy (`initialize`-based) ones carry the negotiated version and the
//!    session id.
//! 2. A `401` or `403 insufficient_scope` activates the *airlock*: requests
//!    pause while the token is refreshed or, if needed, a browser login runs:
//!    RFC 9728 → RFC 8414 discovery, PAR with PKCE and `dpop_jkt`, `iss`
//!    validation, and a DPoP-bound code exchange.
//! 3. The request is retried. The response (JSON, or each event of an SSE
//!    stream) is written to stdout. Failures become JSON-RPC errors, never
//!    silence.
//!
//! ## Modules
//!
//! - [`proxy`]: the [`Proxy`] engine (Streamable HTTP, airlock,
//!   DPoP, refresh).
//! - [`auth`]: [`AuthManager`](auth::AuthManager), the OAuth flows, and
//!   [`OidcConfig`].
//! - [`vault`]: credential storage in the OS keychain or in memory.
//! - [`crypto`]: DPoP keys and proofs.
//! - [`config`]: CLI flags and environment variables.
//! - [`logging`]: the private log directory.
//! - [`templates`]: the default login result pages.
//!
//! ## Running the bridge
//!
//! ```no_run
//! use mcp_passport::{config::Config, run_with_vault, vault::Vault};
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let config = <Config as clap::Parser>::try_parse_from([
//!     "mcp-passport",
//!     "--remote-mcp-url",
//!     "https://mcp.example.com/mcp",
//! ])?;
//! // `run` picks the OS keychain; here credentials stay in memory.
//! let vault = Vault::in_memory("example");
//! run_with_vault(config, vault, tokio::io::stdin(), tokio::io::stdout()).await
//! # }
//! ```
//!
//! ## Sending a single request
//!
//! ```no_run
//! use mcp_passport::auth::OidcConfig;
//! use mcp_passport::config::AuthScheme;
//! use mcp_passport::proxy::Proxy;
//! use mcp_passport::vault::Vault;
//! use serde_json::json;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let proxy = Proxy::new(
//!     "https://mcp.example.com/mcp",
//!     "default_user",
//!     OidcConfig {
//!         client_id: "mcp-passport".into(),
//!         redirect_url: "http://127.0.0.1:8082/callback".into(),
//!         ..Default::default()
//!     },
//!     Vault::keyring(&mcp_passport::vault::service_name_for("https://mcp.example.com/mcp")),
//!     "2025-11-25",
//!     AuthScheme::Bearer,
//! );
//! let reply = proxy
//!     .call(json!({
//!         "jsonrpc": "2.0",
//!         "id": 1,
//!         "method": "tools/list",
//!         "params": {"_meta": {
//!             "io.modelcontextprotocol/protocolVersion": "2026-07-28",
//!             "io.modelcontextprotocol/clientCapabilities": {}
//!         }}
//!     }))
//!     .await?;
//! println!("{reply:?}");
//! # Ok(())
//! # }
//! ```
#![warn(missing_docs)]

pub mod auth;
mod challenge;
pub mod config;
pub mod crypto;
mod discovery;
pub mod logging;
mod mcp;
mod net;
pub mod proxy;
pub mod templates;
pub mod vault;

use crate::auth::{OidcConfig, Timeouts};
use crate::config::Config;
use crate::mcp::Era;
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
        (&config.oidc_issuer, "--oidc-issuer"),
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
        expected_issuer: config.oidc_issuer.clone(),
        request_offline_access: config.oidc_offline_access,
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

    // Task 1: Standalone GET stream (Server -> Client). It only exists for
    // legacy servers, so it starts once a legacy session is established.
    // Modern servers deliver change notifications on `subscriptions/listen`.
    let sse_proxy = proxy.clone();
    let sse_stdout_tx = stdout_tx.clone();
    let sse_handle = tokio::spawn(async move {
        sse_proxy.wait_for_legacy_session().await;
        if let Err(e) = sse_proxy.listen_sse(&sse_url, sse_stdout_tx).await {
            error!("SSE listener failed: {:?}", e);
        }
    });

    // Task 2: Stdio Read Loop (Client -> Server)
    let mut reader = BufReader::new(stdin).lines();
    let mut tasks = JoinSet::new();
    let in_flight: InFlight = Arc::default();

    info!("Ready to proxy MCP stdio messages...");

    loop {
        tokio::select! {
            line_res = reader.next_line() => {
                match line_res {
                    Ok(Some(line)) => {
                        let parsed = serde_json::from_str::<serde_json::Value>(&line).ok();
                        if let Some(target) = parsed.as_ref().and_then(cancelled_request_key) {
                            if let Some((handle, era)) = in_flight.lock().await.remove(&target) {
                                info!("Client cancelled request {}; stopping it.", target);
                                // Dropping the HTTP response closes its stream, which is
                                // how Streamable HTTP signals cancellation. Legacy servers
                                // also expect the notification itself.
                                handle.abort();
                                if era == Era::Modern {
                                    continue;
                                }
                            }
                        }

                        let key = parsed.as_ref().and_then(request_key);
                        let era = parsed.as_ref().map(mcp::era_of).unwrap_or(Era::Legacy);
                        let proxy_task = proxy.clone();
                        let task_stdout_tx = stdout_tx.clone();
                        let task_in_flight = in_flight.clone();
                        let task_key = key.clone();
                        // Held across spawn so the task can't remove its entry
                        // before it is inserted.
                        let mut guard = in_flight.lock().await;
                        let handle = tasks.spawn(async move {
                            process_message(proxy_task, line, task_stdout_tx).await;
                            if let Some(k) = task_key {
                                task_in_flight.lock().await.remove(&k);
                            }
                        });
                        if let Some(k) = key {
                            guard.insert(k, (handle, era));
                        }
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
                    if !e.is_cancelled() {
                        error!("Proxy task failed: {:?}", e);
                    }
                }
            }
        }
    }

    // Cleanup: give in-flight requests a moment to finish, then stop. Long-lived
    // streams (e.g. `subscriptions/listen`) would otherwise keep us alive after
    // the client closed stdin.
    info!("Waiting for remaining tasks to complete...");
    sse_handle.abort();
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        info!("Stopping requests still in flight.");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    // Drop stdout_tx so the writer task can finish
    drop(stdout_tx);
    let _ = stdout_handle.await;

    Ok(())
}

/// How long in-flight requests may run after stdin closes.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Requests being forwarded, by JSON-RPC id, so stdio cancellations can stop them.
type InFlight =
    Arc<tokio::sync::Mutex<std::collections::HashMap<String, (tokio::task::AbortHandle, Era)>>>;

/// The id of a request (a message with both `method` and `id`), as a map key.
fn request_key(msg: &serde_json::Value) -> Option<String> {
    msg.get("method")?;
    msg.get("id").map(|id| id.to_string())
}

/// The target of a `notifications/cancelled`, as a map key.
fn cancelled_request_key(msg: &serde_json::Value) -> Option<String> {
    if msg.get("method")?.as_str()? != "notifications/cancelled" || msg.get("id").is_some() {
        return None;
    }
    msg.pointer("/params/requestId").map(|id| id.to_string())
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
    use axum::response::IntoResponse;
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

    /// Sets the flag when dropped, i.e. when the server stops streaming.
    struct DropFlag(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A server whose `tools/call` streams forever (until the client
    /// disconnects) and which records every message POSTed to it.
    async fn endless_stream_server() -> Result<(
        String,
        Arc<std::sync::atomic::AtomicBool>,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    )> {
        use axum::response::sse::{Event, Sse};
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let posted: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Arc::default();
        let (c, p) = (closed.clone(), posted.clone());
        let app = Router::new().route(
            "/rpc",
            post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let (c, p) = (c.clone(), p.clone());
                async move {
                    p.lock().unwrap().push(body.clone());
                    if body["method"] != "tools/call" {
                        return axum::http::StatusCode::ACCEPTED.into_response();
                    }
                    let guard = DropFlag(c);
                    let stream = futures::stream::unfold(guard, |g| async move {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        let progress = json!({"jsonrpc": "2.0", "method": "notifications/progress",
                            "params": {"progressToken": "t", "progress": 1}});
                        Some((
                            Ok::<_, std::convert::Infallible>(
                                Event::default().data(progress.to_string()),
                            ),
                            g,
                        ))
                    });
                    Sse::new(stream).into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/rpc", listener.local_addr()?);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((url, closed, posted))
    }

    async fn run_cancellation(
        call: serde_json::Value,
    ) -> Result<(bool, Vec<serde_json::Value>, String)> {
        let (url, closed, posted) = endless_stream_server().await?;
        let config = <Config as clap::Parser>::try_parse_from([
            "mcp-passport",
            "--remote-mcp-url",
            &url,
            "--oidc-redirect-url",
            "http://127.0.0.1:1/callback",
        ])?;
        let (mut client_out, server_out) = tokio::io::duplex(64 * 1024);
        let (mut client_in, server_in) = tokio::io::duplex(64 * 1024);
        let run = tokio::spawn(run_with_vault(
            config,
            vault_with_credentials()?,
            server_in,
            server_out,
        ));

        client_in.write_all(format!("{call}\n").as_bytes()).await?;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let cancel = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": call["id"], "reason": "user"}});
        client_in
            .write_all(format!("{cancel}\n").as_bytes())
            .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !closed.load(std::sync::atomic::Ordering::SeqCst)
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let was_closed = closed.load(std::sync::atomic::Ordering::SeqCst);
        drop(client_in);
        tokio::time::timeout(std::time::Duration::from_secs(10), run).await???;

        let mut out = String::new();
        client_out.read_to_string(&mut out).await?;
        let posted = posted.lock().unwrap().clone();
        Ok((was_closed, posted, out))
    }

    #[tokio::test]
    async fn test_modern_cancellation_closes_the_stream() -> Result<()> {
        let call = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "slow", "arguments": {},
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities": {}}}});
        let (closed, posted, out) = run_cancellation(call).await?;
        assert!(closed, "the server must see the response stream close");
        // Streamable HTTP defines no cancellation notification: none is POSTed.
        assert_eq!(posted.len(), 1);
        // Progress may have been forwarded, but never a response for id 5.
        for line in out.lines() {
            let msg: serde_json::Value = serde_json::from_str(line)?;
            assert!(msg.get("id").is_none(), "unexpected response: {line}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_legacy_cancellation_also_forwards_the_notification() -> Result<()> {
        let call = json!({"jsonrpc": "2.0", "id": "c-1", "method": "tools/call",
            "params": {"name": "slow", "arguments": {}}});
        let (closed, posted, _out) = run_cancellation(call).await?;
        assert!(closed);
        assert_eq!(posted.len(), 2);
        assert_eq!(posted[1]["method"], "notifications/cancelled");
        assert_eq!(posted[1]["params"]["requestId"], "c-1");
        Ok(())
    }

    #[test]
    fn test_request_and_cancel_keys() {
        assert_eq!(
            request_key(&json!({"id": 1, "method": "x"})),
            Some("1".into())
        );
        assert_eq!(
            request_key(&json!({"id": "a", "method": "x"})),
            Some("\"a\"".into())
        );
        assert_eq!(request_key(&json!({"id": 1, "result": {}})), None);
        assert_eq!(request_key(&json!({"method": "notify"})), None);
        let cancel = json!({"method": "notifications/cancelled", "params": {"requestId": "a"}});
        assert_eq!(cancelled_request_key(&cancel), Some("\"a\"".into()));
        assert_eq!(cancelled_request_key(&json!({"method": "other"})), None);
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
            oidc_issuer: None,
            oidc_offline_access: false,
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
