//! # Transparent Layer 7 Bridge (Airlock)
//!
//! This module implements the core proxying logic between the AI client's stdio and the
//! remote MCP server's HTTP/SSE interface. It features the "Airlock" mechanism
//! for transparently handling authentication challenges without interrupting the client connection.

use crate::auth::{AuthManager, OidcConfig};
use crate::challenge::WwwAuthenticate;
use crate::config::AuthScheme;
use crate::crypto::DpopKey;
use crate::vault::Vault;
use crate::Result;
use anyhow::Context;
use rand::Rng;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tracing::{error, info, warn};
use url::Url;

/// The main proxy engine that manages the connection and authentication state.
pub struct Proxy {
    /// The HTTP client used for proxying requests.
    http_client: Client,
    /// The base URL of the remote MCP server.
    remote_url: String,
    /// Receiver for the suspension state (Airlock status).
    suspension_rx: watch::Receiver<bool>,
    /// Sender for the suspension state (Airlock status).
    suspension_tx: watch::Sender<bool>,
    /// Secure vault for storing tokens and keys.
    vault: Vault,
    /// Unique identifier for the current user.
    user_id: String,
    /// OIDC configuration and metadata.
    oidc_config: OidcConfig,
    /// Shared authentication manager (lazy-loaded).
    pub auth_manager: Arc<RwLock<Option<Arc<AuthManager>>>>,
    /// The MCP protocol version to use.
    protocol_version: String,
    /// The authentication scheme (Bearer or DPoP).
    auth_scheme: AuthScheme,
    /// Current session ID (for persistent SSE).
    session_id: Mutex<Option<String>>,
    /// Serializes re-authentication attempts.
    reauth_mutex: Mutex<()>,
    /// Outcome of past re-authentication attempts.
    reauth_state: Mutex<ReauthState>,
    /// Credential generation: bumped on every successful re-authentication.
    reauth_count: Arc<std::sync::atomic::AtomicU64>,
    /// Set once a POST to the remote server has succeeded.
    connected_tx: watch::Sender<bool>,
}

/// A fresh token rejected within this window means re-authenticating again
/// would loop.
const AUTH_LOOP_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);

/// What the proxy remembers about re-authentication attempts.
#[derive(Default)]
struct ReauthState {
    /// Number of attempts made, successful or not.
    attempts: u64,
    /// Why the last attempt failed, if it did.
    last_error: Option<String>,
    /// When the last success happened, and the scopes it was for.
    last_success: Option<(std::time::Instant, Option<Vec<String>>)>,
}

/// A token and the DPoP key it is bound to.
struct Credentials {
    token: String,
    key: DpopKey,
}

fn validate_resource_metadata(metadata_url: Option<&str>, remote_url: &str) -> Option<String> {
    let url_str = metadata_url?;

    let m_url = match Url::parse(url_str) {
        Ok(u) => u,
        Err(e) => {
            warn!("Failed to parse resource_metadata URL ({}): {}", url_str, e);
            return None;
        }
    };

    let r_url = match Url::parse(remote_url) {
        Ok(u) => u,
        Err(e) => {
            warn!("Failed to parse remote URL ({}): {}", remote_url, e);
            return None;
        }
    };

    // Same origin (scheme, host and port), so a challenge can neither point us
    // at another host (SSRF) nor downgrade https to http.
    if m_url.origin() != r_url.origin() {
        warn!(
            "SSRF Prevention: resource_metadata origin {} does not match remote origin {}. Rejecting.",
            m_url.origin().ascii_serialization(),
            r_url.origin().ascii_serialization()
        );
        return None;
    }

    Some(url_str.to_string())
}

impl Proxy {
    /// Creates a new Proxy instance.
    pub fn new(
        remote_url: &str,
        user_id: &str,
        oidc_config: OidcConfig,
        vault: Vault,
        protocol_version: &str,
        auth_scheme: AuthScheme,
    ) -> Arc<Self> {
        let (tx, rx) = watch::channel(false);
        let http_client = Client::builder()
            .connect_timeout(crate::auth::CONNECT_TIMEOUT)
            .build()
            .expect("Failed to build HTTP client");
        Arc::new(Self {
            http_client,
            remote_url: remote_url.to_string(),
            suspension_rx: rx,
            suspension_tx: tx,
            vault,
            user_id: user_id.to_string(),
            oidc_config,
            auth_manager: Arc::new(RwLock::new(None)),
            protocol_version: protocol_version.to_string(),
            auth_scheme,
            session_id: Mutex::new(None),
            reauth_mutex: Mutex::new(()),
            reauth_state: Mutex::new(ReauthState::default()),
            reauth_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            connected_tx: watch::channel(false).0,
        })
    }

    /// Loads the token and its DPoP key. A token without its key is unusable
    /// and treated as no credentials.
    fn load_credentials(&self) -> Result<Option<Credentials>> {
        let Some(token) = self.vault.get_token(&self.user_id)? else {
            return Ok(None);
        };
        match self.vault.get_dpop_key(&self.user_id)? {
            Some(bytes) => Ok(Some(Credentials {
                token,
                key: DpopKey::from_bytes(&bytes)?,
            })),
            None => {
                warn!("Stored token has no DPoP key; it will not be used.");
                Ok(None)
            }
        }
    }

    /// The current credential generation.
    fn generation(&self) -> u64 {
        self.reauth_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    async fn ensure_auth_manager(&self, metadata_url: Option<&str>) -> Result<Arc<AuthManager>> {
        {
            let lock = self.auth_manager.read().await;
            if let Some(am) = lock.as_ref() {
                return Ok(am.clone());
            }
        }

        let mut lock = self.auth_manager.write().await;
        // Re-check after acquiring write lock
        if let Some(am) = lock.as_ref() {
            return Ok(am.clone());
        }

        info!(
            "Initializing AuthManager (resource_metadata: {:?})...",
            metadata_url
        );

        let am = AuthManager::discover(
            self.oidc_config.clone(),
            self.remote_url.clone(), // This is the 'resource'
            self.vault.clone(),
            metadata_url,
        )
        .await?;

        let am_shared = Arc::new(am);
        *lock = Some(am_shared.clone());
        Ok(am_shared)
    }

    /// Builds a request to the remote server with the MCP headers and, when a
    /// token is available, the Authorization and DPoP headers.
    async fn build_request(
        &self,
        method: reqwest::Method,
        url: &str,
        credentials: Option<&Credentials>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut request = self
            .http_client
            .request(method.clone(), url)
            .header("MCP-Protocol-Version", &self.protocol_version);

        if let Some(Credentials { token, key }) = credentials {
            let dpop_proof = key.generate_proof_with_ath(method.as_str(), url, Some(token))?;
            let auth_header = match self.auth_scheme {
                AuthScheme::Bearer => format!("Bearer {}", token),
                AuthScheme::Dpop => format!("DPoP {}", token),
            };
            request = request
                .header(AUTHORIZATION, auth_header)
                .header("DPoP", dpop_proof);
        }

        if let Some(s) = &*self.session_id.lock().await {
            request = request.header("MCP-Session-Id", s);
        }
        Ok(request)
    }

    async fn execute_request(
        &self,
        credentials: Option<&Credentials>,
        payload: &Value,
    ) -> Result<reqwest::Response> {
        if credentials.is_none() {
            info!(
                "No credentials for user, sending unauthenticated request to trigger discovery..."
            );
        }
        let request = self
            .build_request(reqwest::Method::POST, &self.remote_url, credentials)
            .await?
            .header(ACCEPT, "application/json, text/event-stream");
        Ok(request.json(payload).send().await?)
    }

    /// Re-authenticates according to a `WWW-Authenticate` challenge.
    async fn reauth_for_challenge(
        &self,
        challenge: &WwwAuthenticate,
        observed_gen: u64,
    ) -> Result<()> {
        // Without a (valid) resource_metadata, discovery falls back to the well-known URIs.
        let metadata_url =
            validate_resource_metadata(challenge.resource_metadata(), &self.remote_url);
        self.trigger_reauth(observed_gen, metadata_url.as_deref(), challenge.scope())
            .await
    }

    /// Handles 401 (expired/missing token) and 403 `insufficient_scope` (step-up).
    /// Returns `true` when the request should be retried.
    async fn handle_auth_challenge(
        &self,
        response: &reqwest::Response,
        observed_gen: u64,
    ) -> Result<bool> {
        let status = response.status();
        if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN {
            return Ok(false);
        }
        let challenge = WwwAuthenticate::parse(response.headers());
        if status == StatusCode::UNAUTHORIZED {
            warn!("401 Unauthorized received. Activating Airlock suspension...");
        } else if challenge.error() == Some("insufficient_scope") {
            warn!(
                "403 Forbidden (insufficient_scope) received. Triggering step-up authentication..."
            );
        } else {
            return Ok(false);
        }
        self.reauth_for_challenge(&challenge, observed_gen).await?;
        Ok(true)
    }

    /// Primary entry point for the stdio -> HTTP bridge.
    ///
    /// Sends one JSON-RPC message to the remote server (attaching DPoP-bound
    /// tokens and managing the Airlock) and writes every message the server
    /// returns for it to `out`: a JSON body, or each event of a
    /// `text/event-stream` response (MCP Streamable HTTP).
    pub async fn handle_request(&self, payload: Value, out: &mpsc::Sender<String>) -> Result<()> {
        let max_retries = 2;
        let mut retry_count = 0;
        let mut loaded_gen: Option<u64> = None;
        let mut credentials = None;

        let response = loop {
            if retry_count > max_retries {
                error!("Maximum retry attempts reached for request. Aborting to prevent infinite loop.");
                anyhow::bail!("Maximum retry attempts reached");
            }

            self.wait_for_airlock().await?;
            let gen = self.generation();
            if loaded_gen != Some(gen) {
                credentials = self.load_credentials()?;
                loaded_gen = Some(gen);
            }

            let response = self.execute_request(credentials.as_ref(), &payload).await?;
            if self.handle_auth_challenge(&response, gen).await? {
                retry_count += 1;
                continue;
            }
            break response;
        };

        let status = response.status();

        // A 404 for a request carrying a session id means the session is gone;
        // the client has to start a new one with `initialize`.
        if status == StatusCode::NOT_FOUND {
            let mut sid = self.session_id.lock().await;
            if let Some(old) = sid.take() {
                warn!("MCP session {} expired (HTTP 404).", old);
                anyhow::bail!("MCP session expired; re-initialize the connection");
            }
        }

        if let Some(sid) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|h| h.to_str().ok())
        {
            let mut sid_lock = self.session_id.lock().await;
            if sid_lock.as_deref() != Some(sid) {
                info!("New MCP Session ID captured: {}", sid);
                *sid_lock = Some(sid.to_string());
            }
        }

        if status.is_success() {
            let _ = self.connected_tx.send(true);
        }

        if status == StatusCode::ACCEPTED || status == StatusCode::NO_CONTENT {
            return Ok(());
        }

        let is_event_stream = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));

        if status.is_success() && is_event_stream {
            return forward_event_stream(response, payload.get("id"), out).await;
        }

        let body = response.bytes().await?;
        if status.is_success() {
            if body.iter().all(u8::is_ascii_whitespace) {
                return Ok(());
            }
            let value: Value = serde_json::from_slice(&body)
                .context("Remote MCP server returned a body that is not JSON")?;
            let _ = out.send(value.to_string()).await;
            return Ok(());
        }

        // Some servers put a JSON-RPC error in a non-2xx response: pass it on as is.
        if let Ok(value) = serde_json::from_slice::<Value>(&body) {
            if value.get("jsonrpc").is_some() && value.get("error").is_some() {
                let _ = out.send(value.to_string()).await;
                return Ok(());
            }
        }
        let text = String::from_utf8_lossy(&body);
        let snippet: String = text.chars().take(200).collect();
        anyhow::bail!(
            "Remote MCP server returned HTTP {}: {}",
            status,
            snippet.trim()
        )
    }

    /// Sends one request and returns the server's response to it.
    ///
    /// Other messages the server streams back (e.g. progress notifications) are
    /// dropped. Returns `Ok(None)` when nothing comes back, as for notifications.
    pub async fn call(&self, payload: Value) -> Result<Option<Value>> {
        let id = payload.get("id").cloned();
        let (tx, mut rx) = mpsc::channel::<String>(16);
        let (res, messages) = tokio::join!(
            async move { self.handle_request(payload, &tx).await },
            async {
                let mut messages = Vec::new();
                while let Some(m) = rx.recv().await {
                    messages.push(m);
                }
                messages
            }
        );
        res?;
        let mut parsed: Vec<Value> = messages
            .iter()
            .filter_map(|m| serde_json::from_str(m).ok())
            .collect();
        let pos = parsed
            .iter()
            .position(|m| id.is_some() && m.get("id") == id.as_ref());
        Ok(match pos {
            Some(i) => Some(parsed.swap_remove(i)),
            None => parsed.pop(),
        })
    }

    /// Resolves once a POST to the remote server has succeeded (so the session
    /// id, if any, is known).
    pub async fn wait_until_connected(&self) {
        let mut rx = self.connected_tx.subscribe();
        let _ = rx.wait_for(|connected| *connected).await;
    }

    /// Runs a re-authentication, or reuses the outcome of one that happened
    /// while waiting.
    ///
    /// `observed_gen` is the credential generation used by the request that was
    /// rejected. Requests rejected together share a single browser login: once
    /// one of them re-authenticates, the others reuse its result (or its
    /// failure). A fresh token rejected again right away is reported as an
    /// authentication loop instead of opening yet another login.
    pub async fn trigger_reauth(
        &self,
        observed_gen: u64,
        metadata_url: Option<&str>,
        scopes: Option<Vec<String>>,
    ) -> Result<()> {
        let attempts_before = self.reauth_state.lock().await.attempts;
        let _guard = self.reauth_mutex.lock().await;

        {
            let state = self.reauth_state.lock().await;
            let current_gen = self.generation();
            let covers = |granted: &Option<Vec<String>>| scopes.is_none() || &scopes == granted;

            if current_gen != observed_gen {
                if state.last_success.as_ref().is_some_and(|(_, g)| covers(g)) {
                    info!("Credentials were renewed by another request; reusing them.");
                    return Ok(());
                }
            } else if state.attempts != attempts_before {
                // An attempt ran while we waited and failed (the generation did not move).
                let reason = state.last_error.clone().unwrap_or_default();
                anyhow::bail!("Re-authentication failed: {}", reason);
            } else if let Some((at, granted)) = &state.last_success {
                if at.elapsed() < AUTH_LOOP_WINDOW && covers(granted) {
                    error!(
                        "Authentication loop detected: a token obtained {:?} ago was rejected.",
                        at.elapsed()
                    );
                    anyhow::bail!(
                        "Authentication loop detected: the server rejected a freshly issued token. \
                         Please check your credentials and environment configuration."
                    );
                }
            }
        }

        let _ = self.suspension_tx.send(true);
        info!("Airlock activated. Performing re-authentication...");

        // `reauthenticate` bounds the interactive wait with `timeouts.auth`.
        let result = async {
            let auth_manager = self.ensure_auth_manager(metadata_url).await?;
            auth_manager
                .reauthenticate(&self.user_id, scopes.clone(), None)
                .await
        }
        .await;

        {
            let mut state = self.reauth_state.lock().await;
            state.attempts += 1;
            match &result {
                Ok(()) => {
                    state.last_error = None;
                    state.last_success = Some((std::time::Instant::now(), scopes));
                    self.reauth_count
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    info!("Re-authentication successful. Deactivating Airlock...");
                }
                Err(e) => {
                    error!("Re-authentication failed: {:?}", e);
                    state.last_error = Some(format!("{e:#}"));
                }
            }
        }
        let _ = self.suspension_tx.send(false);
        result
    }

    async fn wait_for_airlock(&self) -> Result<()> {
        let mut rx = self.suspension_rx.clone();
        while *rx.borrow() {
            rx.changed().await.context("Suspension channel closed")?;
        }
        Ok(())
    }

    pub async fn listen_sse(
        &self,
        sse_url: &str,
        stdout_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<()> {
        use futures::StreamExt;
        use reqwest_eventsource::EventSource;

        let mut loaded_gen: Option<u64> = None;
        let mut credentials = None;
        let mut last_event_id: Option<String> = None;

        loop {
            self.wait_for_airlock().await?;
            let gen = self.generation();
            if loaded_gen != Some(gen) {
                credentials = self.load_credentials()?;
                loaded_gen = Some(gen);
            }
            if credentials.is_none() {
                info!("No credentials for user in SSE listener, sending unauthenticated request to trigger discovery...");
            }

            let mut request = self
                .build_request(reqwest::Method::GET, sse_url, credentials.as_ref())
                .await?;
            if let Some(id) = &last_event_id {
                // Lets the server replay what we missed (resumability).
                request = request.header("Last-Event-ID", id);
            }

            info!("Opening SSE connection to {}...", sse_url);
            let mut source = EventSource::new(request)?;

            while let Some(event) = source.next().await {
                match event {
                    Ok(reqwest_eventsource::Event::Message(message)) => {
                        tracing::debug!(event = %message.event, id = %message.id, "Received SSE message");
                        if !message.id.is_empty() {
                            last_event_id = Some(message.id);
                        }
                        if !message.data.is_empty() {
                            let _ = stdout_tx.send(message.data).await;
                        }
                    }
                    Ok(reqwest_eventsource::Event::Open) => info!("SSE connection established"),
                    Err(reqwest_eventsource::Error::InvalidStatusCode(status, resp)) => {
                        source.close();
                        match status {
                            StatusCode::UNAUTHORIZED => {
                                warn!(
                                    "401 Unauthorized received in SSE listener ({}). Triggering re-authentication...",
                                    sse_url
                                );
                                let challenge = WwwAuthenticate::parse(resp.headers());
                                if let Err(e) = self.reauth_for_challenge(&challenge, gen).await {
                                    error!(
                                        "Re-authentication flow failed in SSE listener: {:?}",
                                        e
                                    );
                                }
                            }
                            StatusCode::METHOD_NOT_ALLOWED => {
                                info!(
                                    "Remote server does not offer an SSE stream at {} (405); SSE listener stopped.",
                                    sse_url
                                );
                                return Ok(());
                            }
                            _ => error!(
                                "SSE error: Invalid status code {} from {}. Response: {:?}",
                                status, sse_url, resp
                            ),
                        }
                        break;
                    }
                    Err(e) => {
                        error!("SSE error connecting to {}: {:?}", sse_url, e);
                        source.close();
                        break;
                    }
                }
            }

            let t = &self.oidc_config.timeouts;
            let jitter_max = t.sse_retry_jitter.as_millis().max(1) as u64;
            let delay = t.sse_retry_base
                + std::time::Duration::from_millis(rand::rng().random::<u64>() % jitter_max);
            warn!("SSE connection lost, retrying in {:?}...", delay);
            tokio::time::sleep(delay).await;
        }
    }
}

/// Forwards each event of a `text/event-stream` POST response to `out`.
///
/// Fails if the stream ends before the response to `request_id` arrived, so
/// that the client gets an error instead of waiting forever.
async fn forward_event_stream(
    response: reqwest::Response,
    request_id: Option<&Value>,
    out: &mpsc::Sender<String>,
) -> Result<()> {
    use eventsource_stream::Eventsource;
    use futures::StreamExt;

    let mut answered = request_id.is_none();
    let mut events = response.bytes_stream().eventsource();
    while let Some(event) = events.next().await {
        let event = event.context("Error reading SSE response stream")?;
        if event.data.is_empty() {
            continue;
        }
        if !answered {
            if let Ok(msg) = serde_json::from_str::<Value>(&event.data) {
                answered = msg.get("id") == request_id
                    && (msg.get("result").is_some() || msg.get("error").is_some());
            }
        }
        let _ = out.send(event.data).await;
    }
    if !answered {
        anyhow::bail!("SSE response stream ended before the response was received");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};

    #[test]
    fn test_proxy_new() {
        let remote_url = "http://example.com/mcp";
        let user_id = "test_user_id";
        let oidc_config = OidcConfig {
            discovery_url: Some("http://example.com/discovery".to_string()),
            client_id: "test_client_id".to_string(),
            redirect_url: "http://localhost:8080/callback".to_string(),
            timeouts: crate::auth::Timeouts::fast(),
            ..Default::default()
        };
        let protocol_version = "2024-11-05";
        let auth_scheme = AuthScheme::Dpop;

        let proxy = Proxy::new(
            remote_url,
            user_id,
            oidc_config.clone(),
            Vault::in_memory("test_service"),
            protocol_version,
            auth_scheme,
        );

        assert_eq!(proxy.remote_url, remote_url);
        assert_eq!(proxy.user_id, user_id);
        assert_eq!(proxy.oidc_config.discovery_url, oidc_config.discovery_url);
        assert_eq!(proxy.oidc_config.client_id, oidc_config.client_id);
        assert_eq!(proxy.protocol_version, protocol_version);
        assert_eq!(proxy.auth_scheme, auth_scheme);
    }

    #[test]
    fn test_validate_resource_metadata() {
        let remote_url = "http://localhost:8081/rpc";
        let check = |m: &str| validate_resource_metadata(Some(m), remote_url);

        assert_eq!(
            check("http://localhost:8081/discovery"),
            Some("http://localhost:8081/discovery".to_string())
        );
        assert_eq!(check("http://attacker.com/evil"), None);
        assert_eq!(check("http://test.localhost:8081/discovery"), None);
        assert_eq!(check("http://localhost:8082/discovery"), None);
        assert_eq!(check("not_a_valid_url"), None);
        assert_eq!(validate_resource_metadata(None, remote_url), None);
        assert_eq!(
            validate_resource_metadata(Some("http://localhost:8081/d"), "not_a_valid_url"),
            None
        );

        // Scheme downgrade and default-port equivalence.
        let https = "https://mcp.example.com/rpc";
        assert_eq!(
            validate_resource_metadata(Some("http://mcp.example.com/meta"), https),
            None
        );
        assert_eq!(
            validate_resource_metadata(Some("https://mcp.example.com:443/meta"), https),
            Some("https://mcp.example.com:443/meta".to_string())
        );
    }

    #[tokio::test]
    async fn test_proxy_ensure_auth_manager_no_discovery() {
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
        // This should fail because no discovery and no overrides
        let res = proxy.ensure_auth_manager(None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_proxy_handle_request_no_content() -> Result<()> {
        let mcp_app = Router::new().route(
            "/rpc",
            post(|| async move { axum::http::StatusCode::NO_CONTENT }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());
        tokio::spawn(async move {
            let _ = axum::serve(listener, mcp_app).await;
        });

        let vault = Vault::in_memory("svc");
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
        vault.store_token("user", "token")?;
        vault.store_dpop_key("user", &crate::crypto::DpopKey::generate().to_bytes())?;

        let res = proxy
            .call(serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "test"}))
            .await?;
        assert_eq!(res, None);
        Ok(())
    }

    fn test_proxy(url: &str, oidc: OidcConfig) -> Arc<Proxy> {
        Proxy::new(
            url,
            "user",
            OidcConfig {
                client_id: "c".into(),
                timeouts: crate::auth::Timeouts::fast(),
                ..oidc
            },
            Vault::in_memory("svc"),
            "v1",
            AuthScheme::Bearer,
        )
    }

    /// A proxy whose AuthManager can never be built (no discovery possible).
    fn undiscoverable_proxy() -> Arc<Proxy> {
        test_proxy(
            "http://localhost:1/rpc",
            OidcConfig {
                redirect_url: "r".into(),
                ..Default::default()
            },
        )
    }

    #[tokio::test]
    async fn test_proxy_handle_request_max_retries() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let rpc_url = format!("http://{}/rpc", listener.local_addr()?);
        let proxy = test_proxy(
            &rpc_url,
            OidcConfig {
                redirect_url: "http://127.0.0.1:1/callback".into(),
                ..Default::default()
            },
        );

        // The server rejects every request, and "someone" renews the credentials
        // each time, so every re-auth is skipped and the request is retried.
        let (c, p) = (counter.clone(), proxy.clone());
        let mcp_app = Router::new().route(
            "/rpc",
            post(move || {
                let (c, p) = (c.clone(), p.clone());
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    {
                        let mut state = p.reauth_state.lock().await;
                        state.last_success = Some((std::time::Instant::now(), None));
                    }
                    p.reauth_count.fetch_add(1, Ordering::SeqCst);
                    (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized")
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, mcp_app).await;
        });

        let err = proxy
            .call(serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "test"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Maximum retry attempts reached"));
        // Initial attempt + 2 retries.
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_reauth_failure_resets_circuit_breaker() -> Result<()> {
        let proxy = undiscoverable_proxy();

        let first = proxy.trigger_reauth(0, None, None).await;
        assert!(first.is_err());
        assert!(proxy.reauth_state.lock().await.last_success.is_none());
        assert!(!*proxy.suspension_rx.borrow(), "airlock must be released");

        // A failed attempt must not arm the loop detector: retrying later runs
        // the flow again instead of reporting an authentication loop.
        let second = proxy.trigger_reauth(0, None, None).await;
        let err = second.unwrap_err().to_string();
        assert!(!err.contains("Authentication loop detected"), "{err}");
        assert_eq!(proxy.reauth_state.lock().await.attempts, 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_trigger_reauth_reuses_renewal_by_other_request() -> Result<()> {
        let proxy = undiscoverable_proxy();
        // Another request re-authenticated after our credentials were loaded.
        proxy.reauth_state.lock().await.last_success = Some((std::time::Instant::now(), None));
        proxy
            .reauth_count
            .store(1, std::sync::atomic::Ordering::SeqCst);

        // No network access happens: the renewal is reused.
        proxy.trigger_reauth(0, None, None).await?;
        assert_eq!(proxy.reauth_state.lock().await.attempts, 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_trigger_reauth_step_up_not_covered_by_plain_renewal() -> Result<()> {
        let proxy = undiscoverable_proxy();
        proxy.reauth_state.lock().await.last_success = Some((std::time::Instant::now(), None));
        proxy
            .reauth_count
            .store(1, std::sync::atomic::Ordering::SeqCst);

        // A step-up for new scopes still needs its own login (which fails here).
        let res = proxy
            .trigger_reauth(0, None, Some(vec!["admin".into()]))
            .await;
        assert!(res.is_err());
        assert_eq!(proxy.reauth_state.lock().await.attempts, 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_trigger_reauth_detects_loop() -> Result<()> {
        let proxy = undiscoverable_proxy();
        // We re-authenticated just now and the request with that token (gen 1)
        // was rejected again.
        proxy.reauth_state.lock().await.last_success = Some((std::time::Instant::now(), None));
        proxy
            .reauth_count
            .store(1, std::sync::atomic::Ordering::SeqCst);

        let err = proxy.trigger_reauth(1, None, None).await.unwrap_err();
        assert!(err.to_string().contains("Authentication loop detected"));

        // An old success does not count as a loop.
        proxy.reauth_state.lock().await.last_success =
            Some((std::time::Instant::now() - AUTH_LOOP_WINDOW * 2, None));
        let err = proxy.trigger_reauth(1, None, None).await.unwrap_err();
        assert!(!err.to_string().contains("Authentication loop detected"));
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_concurrent_failures_share_one_attempt() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Discovery is slow and fails, so the second request waits on the
        // first attempt and must reuse its failure instead of starting a new one.
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = Router::new().fallback(move || {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                axum::http::StatusCode::NOT_FOUND
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let proxy = test_proxy(
            &format!("{base}/rpc"),
            OidcConfig {
                redirect_url: "r".into(),
                ..Default::default()
            },
        );

        let p1 = proxy.clone();
        let first = tokio::spawn(async move { p1.trigger_reauth(0, None, None).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let second = proxy.trigger_reauth(0, None, None).await;

        assert!(first.await?.is_err());
        let err = second.unwrap_err().to_string();
        assert!(err.contains("Re-authentication failed"), "{err}");
        assert_eq!(proxy.reauth_state.lock().await.attempts, 1);
        // One discovery run: the path-inserted and the root well-known URIs.
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_wait_for_airlock() -> Result<()> {
        let proxy = Proxy::new(
            "http://localhost:1/rpc",
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

        // Initially not suspended
        let p = proxy.clone();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), p.wait_for_airlock())
            .await?;

        // Manually activate airlock
        let _ = proxy.suspension_tx.send(true);
        let p2 = proxy.clone();
        let handle = tokio::spawn(async move {
            let _ = p2.wait_for_airlock().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = proxy.suspension_tx.send(false);

        tokio::time::timeout(std::time::Duration::from_millis(100), handle).await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_listen_sse_retry_logic() -> Result<()> {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let proxy = Proxy::new(
            "http://localhost:1/rpc",
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

        let p = proxy.clone();
        let handle = tokio::spawn(async move {
            let _ = p.listen_sse("http://localhost:1/sse", tx).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn test_listen_sse_failure() -> Result<()> {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let proxy = Proxy::new(
            "http://localhost:1/rpc",
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
        // It will retry infinitely, so we just want to see it starting and failing once.
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            proxy.listen_sse("http://localhost:1/sse", tx),
        )
        .await;
        assert!(res.is_err()); // Timeout means it's still retrying
        Ok(())
    }
}
