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
use tracing::{debug, error, info, warn};
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
    /// Mutex to prevent concurrent re-authentication attempts.
    reauth_mutex: Mutex<()>,
    /// Timestamp of the last successful re-authentication.
    last_reauth: Mutex<Option<std::time::Instant>>,
    /// Counter for re-authentication attempts.
    reauth_count: Arc<std::sync::atomic::AtomicU64>,
    /// Set once a POST to the remote server has succeeded.
    connected_tx: watch::Sender<bool>,
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

    if m_url.host_str() != r_url.host_str() || m_url.port() != r_url.port() {
        warn!(
            "SSRF Prevention: resource_metadata host/port ({:?}:{:?}) does not match remote host/port ({:?}:{:?}). Rejecting.",
            m_url.host_str(),
            m_url.port(),
            r_url.host_str(),
            r_url.port()
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
            last_reauth: Mutex::new(None),
            reauth_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            connected_tx: watch::channel(false).0,
        })
    }

    fn load_credentials(&self) -> Result<(Option<String>, Option<DpopKey>)> {
        let token_opt = self.vault.get_token(&self.user_id)?;
        let dpop_key_opt = if token_opt.is_some() {
            match self.vault.get_dpop_key(&self.user_id)? {
                Some(bytes) => Some(DpopKey::from_bytes(&bytes)?),
                None => None,
            }
        } else {
            None
        };
        Ok((token_opt, dpop_key_opt))
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
        credentials: Option<(&str, &DpopKey)>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut request = self
            .http_client
            .request(method.clone(), url)
            .header("MCP-Protocol-Version", &self.protocol_version);

        if let Some((token, dpop_key)) = credentials {
            let dpop_proof = dpop_key.generate_proof_with_ath(method.as_str(), url, Some(token))?;
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
        token_opt: Option<&String>,
        dpop_key_opt: Option<&DpopKey>,
        payload: &Value,
    ) -> Result<Option<reqwest::Response>> {
        let credentials = match (token_opt, dpop_key_opt) {
            (Some(token), Some(key)) => Some((token.as_str(), key)),
            (Some(_), None) => {
                info!("No DPoP key found for user, triggering re-authentication...");
                self.trigger_reauth(None, None, None).await?;
                return Ok(None);
            }
            (None, _) => {
                info!("No token found for user, sending unauthenticated request to trigger discovery...");
                None
            }
        };

        let request = self
            .build_request(reqwest::Method::POST, &self.remote_url, credentials)
            .await?
            .header(ACCEPT, "application/json, text/event-stream");
        Ok(Some(request.json(payload).send().await?))
    }

    /// Re-authenticates according to a `WWW-Authenticate` challenge.
    async fn reauth_for_challenge(
        &self,
        challenge: &WwwAuthenticate,
        token_opt: Option<&str>,
    ) -> Result<()> {
        // Without a (valid) resource_metadata, discovery falls back to the well-known URIs.
        let metadata_url =
            validate_resource_metadata(challenge.resource_metadata(), &self.remote_url);
        self.trigger_reauth(token_opt, metadata_url.as_deref(), challenge.scope())
            .await
    }

    /// Handles 401 (expired/missing token) and 403 `insufficient_scope` (step-up).
    /// Returns `true` when the request should be retried.
    async fn handle_auth_challenge(
        &self,
        response: &reqwest::Response,
        token_opt: Option<&str>,
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
        self.reauth_for_challenge(&challenge, token_opt).await?;
        Ok(true)
    }

    /// Primary entry point for the stdio -> HTTP bridge.
    ///
    /// Sends one JSON-RPC message to the remote server (attaching DPoP-bound
    /// tokens and managing the Airlock) and writes every message the server
    /// returns for it to `out`: a JSON body, or each event of a
    /// `text/event-stream` response (MCP Streamable HTTP).
    pub async fn handle_request(&self, payload: Value, out: &mpsc::Sender<String>) -> Result<()> {
        let mut retry_count = 0;
        let max_retries = 2;

        let mut last_reauth_count: Option<u64> = None;
        let mut token_opt = None;
        let mut dpop_key_opt: Option<DpopKey> = None;

        let response = loop {
            if retry_count > max_retries {
                error!("Maximum retry attempts reached for request. Aborting to prevent infinite loop.");
                anyhow::bail!("Maximum retry attempts reached");
            }

            self.wait_for_airlock().await?;
            let current_reauth_count = self.reauth_count.load(std::sync::atomic::Ordering::Relaxed);

            if last_reauth_count != Some(current_reauth_count) {
                let (new_token, new_dpop) = self.load_credentials()?;
                token_opt = new_token;
                dpop_key_opt = new_dpop;
                last_reauth_count = Some(current_reauth_count);
            }

            let response = match self
                .execute_request(token_opt.as_ref(), dpop_key_opt.as_ref(), &payload)
                .await?
            {
                Some(resp) => resp,
                None => {
                    retry_count += 1;
                    continue;
                }
            };

            if self
                .handle_auth_challenge(&response, token_opt.as_deref())
                .await?
            {
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

    pub async fn trigger_reauth(
        &self,
        failing_token: Option<&str>,
        metadata_url: Option<&str>,
        scopes: Option<Vec<String>>,
    ) -> Result<()> {
        let initial_count = self.reauth_count.load(std::sync::atomic::Ordering::Relaxed);
        let _guard = self.reauth_mutex.lock().await;

        // Re-check if re-authentication is still needed after acquiring the lock.
        // If another task just finished re-authenticating, the token in the vault will be different or present.
        let current_token = self.vault.get_token(&self.user_id)?;
        let current_count = self.reauth_count.load(std::sync::atomic::Ordering::Relaxed);

        debug!(
            "Re-auth redundant check: failing={:?}, current={:?}, count={}/{}, scopes={:?}",
            failing_token.map(|t| &t[..std::cmp::min(8, t.len())]),
            current_token
                .as_deref()
                .map(|t| &t[..std::cmp::min(8, t.len())]),
            initial_count,
            current_count,
            scopes
        );

        // If airlock is already active, someone else is handling it.
        // Wait for it to clear and then return.
        if *self.suspension_rx.borrow() {
            info!("Airlock already active, waiting for it to clear...");
            drop(_guard); // Release lock while waiting for airlock
            self.wait_for_airlock().await?;
            return Ok(());
        }

        if current_count > initial_count && scopes.is_none() {
            info!("Re-authentication occurred while waiting for lock. Skipping redundant re-auth.");
            return Ok(());
        }

        if let (Some(failing), Some(current)) = (failing_token, current_token.as_deref()) {
            if failing != current && scopes.is_none() {
                info!(
                    "Token has already been updated by another task (failing: {}, current: {}). Skipping redundant re-auth.",
                    &failing[..std::cmp::min(8, failing.len())],
                    &current[..std::cmp::min(8, current.len())]
                );
                return Ok(());
            }
        } else if failing_token.is_none() && current_token.is_some() && scopes.is_none() {
            info!("Token was missing but is now present. Skipping redundant re-auth.");
            return Ok(());
        }

        // Circuit Breaker: prevent rapid consecutive re-authentications
        let now = std::time::Instant::now();
        {
            let mut last = self.last_reauth.lock().await;
            if let Some(t) = *last {
                let elapsed = now.duration_since(t);

                if elapsed < std::time::Duration::from_secs(5) {
                    if current_count > initial_count {
                        info!("Count increased during cooldown, skipping redundant re-auth.");
                        return Ok(());
                    }

                    // If we just re-authenticated successfully (count increased), and we ALREADY HAVE a new token,
                    // but we still got a 401, we should NOT re-auth immediately again.
                    // This prevents infinite loops if the new token is being rejected.
                    if current_count > 0 && current_token.is_some() {
                        warn!(
                            "Fresh token was rejected. Skipping immediate re-auth to prevent loop."
                        );
                        return Ok(());
                    }

                    warn!("Re-authentication triggered very rapidly (within 5s).");
                }

                if elapsed < std::time::Duration::from_secs(1) {
                    error!("Authentication loop detected. Re-authentication triggered too frequently (within 1s).");
                    return Err(anyhow::anyhow!("Authentication loop detected. Please check your credentials and environment configuration."));
                }
            }
            *last = Some(now);
        }

        let _ = self.suspension_tx.send(true);
        info!("Airlock activated. Performing re-authentication...");

        // Clear invalid token from vault ONLY if it's still the one failing and not a step-up
        if scopes.is_none() {
            if let (Some(failing), Some(current)) = (failing_token, current_token.as_deref()) {
                if failing == current {
                    let _ = self.vault.delete_token(&self.user_id);
                }
            } else if failing_token.is_none() {
                // If it was missing from the start, we don't need to delete anything,
                // but we should check if it's still missing.
                if current_token.is_some() {
                    info!("Token appeared while preparing re-auth, skipping.");
                    let _ = self.suspension_tx.send(false);
                    return Ok(());
                }
            }
        }

        let auth_manager_res = self.ensure_auth_manager(metadata_url).await;

        let auth_manager = match auth_manager_res {
            Ok(am) => am,
            Err(e) => {
                error!("Failed to ensure AuthManager: {:?}", e);
                let _ = self.suspension_tx.send(false);
                {
                    let mut last = self.last_reauth.lock().await;
                    *last = None;
                }
                return Err(e);
            }
        };

        // `reauthenticate` bounds the interactive wait with `timeouts.auth`.
        match auth_manager
            .reauthenticate(&self.user_id, scopes, None)
            .await
        {
            Ok(()) => {
                self.reauth_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                info!("Re-authentication successful. Deactivating Airlock...");
                let _ = self.suspension_tx.send(false);
                Ok(())
            }
            Err(e) => {
                error!("Re-authentication failed: {:?}", e);
                let _ = self.suspension_tx.send(false);
                {
                    let mut last = self.last_reauth.lock().await;
                    *last = None;
                }
                Err(e)
            }
        }
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

        let mut last_reauth_count: Option<u64> = None;
        let mut token_opt = None;
        let mut dpop_key_opt: Option<DpopKey> = None;
        let mut last_event_id: Option<String> = None;

        loop {
            self.wait_for_airlock().await?;
            let current_reauth_count = self.reauth_count.load(std::sync::atomic::Ordering::Relaxed);

            if last_reauth_count != Some(current_reauth_count) {
                let (new_token, new_dpop) = self.load_credentials()?;
                token_opt = new_token;
                dpop_key_opt = new_dpop;
                last_reauth_count = Some(current_reauth_count);
            }

            let credentials = match (token_opt.as_deref(), dpop_key_opt.as_ref()) {
                (Some(token), Some(key)) => Some((token, key)),
                (Some(_), None) => {
                    info!("No DPoP key found for user in SSE listener, triggering re-authentication...");
                    self.trigger_reauth(None, None, None).await?;
                    continue;
                }
                (None, _) => {
                    info!("No token found for user in SSE listener, sending unauthenticated request to trigger discovery...");
                    None
                }
            };

            let mut request = self
                .build_request(reqwest::Method::GET, sse_url, credentials)
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
                                if let Err(e) = self
                                    .reauth_for_challenge(&challenge, token_opt.as_deref())
                                    .await
                                {
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

        // Match
        let valid = validate_resource_metadata(Some("http://localhost:8081/discovery"), remote_url);
        assert_eq!(valid, Some("http://localhost:8081/discovery".to_string()));

        // Mismatch
        let invalid = validate_resource_metadata(Some("http://attacker.com/evil"), remote_url);
        assert_eq!(invalid, None);

        // Missing
        let missing = validate_resource_metadata(None, remote_url);
        assert_eq!(missing, None);

        // Invalid metadata URL (parsing fails)
        let invalid_metadata_url = validate_resource_metadata(Some("not_a_valid_url"), remote_url);
        assert_eq!(invalid_metadata_url, None);

        // Invalid remote URL (parsing fails)
        let invalid_remote_url =
            validate_resource_metadata(Some("http://localhost:8081/discovery"), "not_a_valid_url");
        assert_eq!(invalid_remote_url, None);

        // Subdomain mismatch
        let subdomain_mismatch =
            validate_resource_metadata(Some("http://test.localhost:8081/discovery"), remote_url);
        assert_eq!(subdomain_mismatch, None);

        // Different ports, but hosts match
        let different_port =
            validate_resource_metadata(Some("http://localhost:8082/discovery"), remote_url);
        assert_eq!(different_port, None);
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
    async fn test_proxy_handle_request_max_retries() -> Result<()> {
        use axum::routing::post;
        use axum::Router;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let mcp_app = Router::new().route(
            "/rpc",
            post(move || {
                let c = counter_clone.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        [(
                            "WWW-Authenticate",
                            "Bearer realm=\"mcp\", resource_metadata=\"http://localhost/discovery\"",
                        )],
                        "Unauthorized",
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());
        tokio::spawn(async move {
            let _ = axum::serve(listener, mcp_app).await;
        });

        let vault = Vault::in_memory("svc_retry");
        let proxy = Proxy::new(
            &rpc_url,
            "user_retry",
            OidcConfig {
                client_id: "c".into(),
                redirect_url: "http://127.0.0.1:8080/callback".into(),
                timeouts: crate::auth::Timeouts::fast(),
                ..Default::default()
            },
            vault.clone(),
            "v1",
            AuthScheme::Bearer,
        );

        // Background task to keep updating the token so trigger_reauth returns Ok(()) (redundant check)
        let vault_clone = vault.clone();
        let stop_updating = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_updating_clone = stop_updating.clone();
        tokio::spawn(async move {
            let mut i = 0;
            while !stop_updating_clone.load(Ordering::SeqCst) {
                let _ = vault_clone.store_token("user_retry", &format!("token-{}", i));
                let _ = vault_clone
                    .store_dpop_key("user_retry", &crate::crypto::DpopKey::generate().to_bytes());
                i += 1;
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                if i > 1000 {
                    break;
                } // Safety break
            }
        });

        let res = proxy
            .call(serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "test"}))
            .await;
        stop_updating.store(true, Ordering::SeqCst);

        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        println!("Error message: {}", err_msg);
        assert!(err_msg.contains("Maximum retry attempts reached"));

        // Initial (retry_count=0) + Retry 1 (retry_count=1) + Retry 2 (retry_count=2) = 3 attempts
        // When retry_count becomes 3, it bails before the 4th attempt.
        assert_eq!(counter.load(Ordering::SeqCst), 3);

        Ok(())
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

    #[tokio::test]
    async fn test_proxy_reauth_failure_resets_circuit_breaker() -> Result<()> {
        let proxy = Proxy::new(
            "http://localhost:1/rpc",
            "user",
            OidcConfig {
                client_id: "c".into(),
                redirect_url: "r".into(),
                auth_url_override: Some("http://localhost:1/auth".into()),
                token_url_override: Some("http://localhost:1/token".into()),
                par_url_override: Some("http://localhost:1/par".into()),
                timeouts: crate::auth::Timeouts::fast(),
                ..Default::default()
            },
            Vault::in_memory("svc"),
            "v1",
            AuthScheme::Bearer,
        );

        // First attempt fails (the redirect URL is invalid, so no loopback server).
        let first = proxy.trigger_reauth(None, None, None).await;
        assert!(first.is_err());
        assert!(proxy.last_reauth.lock().await.is_none());

        // A failed attempt must not arm the loop detector: retrying right away
        // runs the flow again (and fails for the same reason) instead of
        // reporting an authentication loop.
        let second = proxy.trigger_reauth(None, None, None).await;
        let err = second.unwrap_err().to_string();
        assert!(!err.contains("Authentication loop detected"), "{err}");
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_trigger_reauth_already_active() -> Result<()> {
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

        // Manually activate airlock
        let _ = proxy.suspension_tx.send(true);

        // Deactivate airlock in background
        let p = proxy.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = p.suspension_tx.send(false);
        });

        // trigger_reauth should wait for airlock to clear and then return Ok(())
        let res = proxy.trigger_reauth(None, None, None).await;
        assert!(res.is_ok());
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
    async fn test_proxy_trigger_reauth_cooldown() -> Result<()> {
        let vault = Vault::in_memory("svc");
        let proxy = Proxy::new(
            "http://localhost:1/rpc",
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

        // Set last_reauth to now and reauth_count to 1
        {
            let mut lr = proxy.last_reauth.lock().await;
            *lr = Some(std::time::Instant::now());
            proxy
                .reauth_count
                .store(1, std::sync::atomic::Ordering::Relaxed);
        }

        // trigger_reauth should return Ok(()) and warn about fresh token rejected
        let res = proxy.trigger_reauth(Some("token"), None, None).await;
        assert!(res.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_trigger_reauth_redundant_skip() -> Result<()> {
        let vault = Vault::in_memory("svc");
        let proxy = Proxy::new(
            "http://localhost:1/rpc",
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
        vault.store_token("user", "new_token")?;

        // trigger_reauth with an old failing token should skip re-auth if current token is different
        let res = proxy.trigger_reauth(Some("old_token"), None, None).await;
        assert!(res.is_ok());
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
