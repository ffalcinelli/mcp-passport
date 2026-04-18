//! # Transparent Layer 7 Bridge (Airlock)
//!
//! This module implements the core proxying logic between the AI client's stdio and the
//! remote MCP server's HTTP/SSE interface. It features the "Airlock" mechanism
//! for transparently handling authentication challenges without interrupting the client connection.

use crate::auth::{AuthManager, OidcConfig};
use crate::config::AuthScheme;
use crate::crypto::DpopKey;
use crate::vault::Vault;
use crate::Result;
use anyhow::Context;
use reqwest::{header::HeaderMap, Client, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{watch, Mutex, RwLock};
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
    pub auth_manager: Arc<RwLock<Option<AuthManager>>>,
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
    reauth_count: Arc<tokio::sync::RwLock<u64>>,
}

#[derive(Debug, Default)]
struct WwwAuthenticate {
    resource_metadata: Option<String>,
    scope: Option<Vec<String>>,
    error: Option<String>,
}

impl WwwAuthenticate {
    fn parse(headers: &HeaderMap) -> Self {
        let mut result = Self::default();
        if let Some(auth_val) = headers
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|h| h.to_str().ok())
        {
            debug!("Parsing WWW-Authenticate: {}", auth_val);

            // Basic parsing for resource_metadata and scope
            if let Some(rm) = extract_param(auth_val, "resource_metadata") {
                result.resource_metadata = Some(rm);
            }
            if let Some(sc) = extract_param(auth_val, "scope") {
                result.scope = Some(sc.split_whitespace().map(|s| s.to_string()).collect());
            }
            if let Some(err) = extract_param(auth_val, "error") {
                result.error = Some(err);
            }
        }
        result
    }
}

fn extract_param(header: &str, param: &str) -> Option<String> {
    let needle = format!("{}=", param);
    if let Some(start) = header.find(&needle) {
        let val_start = start + needle.len();
        let remainder = &header[val_start..];
        if let Some(stripped) = remainder.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                return Some(stripped[..end].to_string());
            }
        } else {
            // Unquoted: take until comma or end of string
            let end = remainder.find(',').unwrap_or(remainder.len());
            return Some(remainder[..end].trim().to_string());
        }
    }
    None
}

impl Proxy {
    /// Creates a new Proxy instance.
    pub fn new(
        remote_url: &str,
        user_id: &str,
        oidc_config: OidcConfig,
        service: &str,
        protocol_version: &str,
        auth_scheme: AuthScheme,
    ) -> Arc<Self> {
        let (tx, rx) = watch::channel(false);
        Arc::new(Self {
            http_client: Client::new(),
            remote_url: remote_url.to_string(),
            suspension_rx: rx,
            suspension_tx: tx,
            vault: Vault::new(service),
            user_id: user_id.to_string(),
            oidc_config,
            auth_manager: Arc::new(RwLock::new(None)),
            protocol_version: protocol_version.to_string(),
            auth_scheme,
            session_id: Mutex::new(None),
            reauth_mutex: Mutex::new(()),
            last_reauth: Mutex::new(None),
            reauth_count: Arc::new(tokio::sync::RwLock::new(0)),
        })
    }

    async fn ensure_auth_manager(&self, metadata_url: Option<&str>) -> Result<Arc<AuthManager>> {
        {
            let lock = self.auth_manager.read().await;
            if let Some(am) = lock.as_ref() {
                return Ok(Arc::new(am.clone()));
            }
        }

        let mut lock = self.auth_manager.write().await;
        // Re-check after acquiring write lock
        if let Some(am) = lock.as_ref() {
            return Ok(Arc::new(am.clone()));
        }

        let discovery_url = metadata_url
            .map(|s| s.to_string())
            .or_else(|| self.oidc_config.discovery_url.clone());

        info!(
            "Performing dynamic discovery for AuthManager (url: {:?})...",
            discovery_url
        );

        let am = AuthManager::discover(
            self.oidc_config.clone(),
            self.remote_url.clone(), // This is the 'resource'
            &self.vault.service,
            metadata_url,
        )
        .await?;

        let am_shared = Arc::new(am);
        *lock = Some((*am_shared).clone());
        Ok(am_shared)
    }

    /// Primary entry point for stdio -> HTTP bridge.
    /// It reads JSON-RPC payloads, attaches DPoP-bound tokens, and manages the Airlock.
    pub async fn handle_request(self: Arc<Self>, payload: Value) -> Result<Value> {
        let mut retry_count = 0;
        let max_retries = 2;

        loop {
            if retry_count > max_retries {
                error!("Maximum retry attempts reached for request. Aborting to prevent infinite loop.");
                anyhow::bail!("Maximum retry attempts reached");
            }

            self.wait_for_airlock().await?;

            let token_opt = self.vault.get_token(&self.user_id)?;

            let response = if let Some(ref token) = token_opt {
                let dpop_key = match self.vault.get_dpop_key(&self.user_id)? {
                    Some(bytes) => DpopKey::from_bytes(&bytes)?,
                    None => {
                        info!("No DPoP key found for user, triggering re-authentication...");
                        self.trigger_reauth(None, None, None).await?;
                        retry_count += 1;
                        continue;
                    }
                };

                let dpop_proof =
                    dpop_key.generate_proof_with_ath("POST", &self.remote_url, Some(token))?;

                let auth_header = match self.auth_scheme {
                    AuthScheme::Bearer => format!("Bearer {}", token),
                    AuthScheme::Dpop => format!("DPoP {}", token),
                };

                let mut request = self
                    .http_client
                    .post(&self.remote_url)
                    .header("Authorization", auth_header)
                    .header("DPoP", dpop_proof)
                    .header("MCP-Protocol-Version", &self.protocol_version);

                let sid = {
                    let sid_lock = self.session_id.lock().await;
                    sid_lock.clone()
                };

                if let Some(s) = sid {
                    request = request.header("MCP-Session-Id", s);
                }

                request.json(&payload).send().await?
            } else {
                // No token. Send unauthenticated request to trigger discovery via 401
                info!(
                    "No token found for user, sending unauthenticated request to trigger discovery..."
                );
                let mut request = self
                    .http_client
                    .post(&self.remote_url)
                    .header("MCP-Protocol-Version", &self.protocol_version);

                let sid = {
                    let sid_lock = self.session_id.lock().await;
                    sid_lock.clone()
                };
                if let Some(s) = sid {
                    request = request.header("MCP-Session-Id", s);
                }

                request.json(&payload).send().await?
            };

            if response.status() == StatusCode::UNAUTHORIZED {
                warn!("401 Unauthorized received. Activating Airlock suspension...");
                let challenge = WwwAuthenticate::parse(response.headers());

                let metadata_url = challenge.resource_metadata.or_else(|| {
                    // Fallback to well-known at root if header is missing
                    info!("WWW-Authenticate missing resource_metadata, falling back to root well-known...");
                    Url::parse(&self.remote_url).ok().and_then(|u| {
                        u.join("/.well-known/oauth-protected-resource")
                            .ok()
                            .map(|url| url.to_string())
                    })
                });

                self.trigger_reauth(
                    token_opt.as_deref(),
                    metadata_url.as_deref(),
                    challenge.scope,
                )
                .await?;

                // Retry the request after re-authentication
                retry_count += 1;
                continue;
            }

            if response.status() == StatusCode::FORBIDDEN {
                let challenge = WwwAuthenticate::parse(response.headers());
                if challenge.error.as_deref() == Some("insufficient_scope") {
                    warn!("403 Forbidden (insufficient_scope) received. Triggering step-up authentication...");

                    let metadata_url = challenge.resource_metadata.or_else(|| {
                        Url::parse(&self.remote_url).ok().and_then(|u| {
                            u.join("/.well-known/oauth-protected-resource")
                                .ok()
                                .map(|url| url.to_string())
                        })
                    });

                    self.trigger_reauth(
                        token_opt.as_deref(),
                        metadata_url.as_deref(),
                        challenge.scope,
                    )
                    .await?;
                    retry_count += 1;
                    continue;
                }
            }

            // Capture Session ID if returned
            if let Some(sid) = response
                .headers()
                .get("mcp-session-id")
                .and_then(|h| h.to_str().ok())
            {
                let mut sid_lock = self.session_id.lock().await;
                if sid_lock.as_ref().map(|s| s.as_str()) != Some(sid) {
                    info!("New MCP Session ID captured: {}", sid);
                    *sid_lock = Some(sid.to_string());
                }
            }

            if response.status() == StatusCode::NO_CONTENT {
                return Ok(Value::Null);
            }

            let body = response.json::<Value>().await?;
            return Ok(body);
        }
    }

    async fn trigger_reauth(
        &self,
        failing_token: Option<&str>,
        metadata_url: Option<&str>,
        scopes: Option<Vec<String>>,
    ) -> Result<()> {
        let initial_count = { *self.reauth_count.read().await };
        let _guard = self.reauth_mutex.lock().await;

        // Re-check if re-authentication is still needed after acquiring the lock.
        // If another task just finished re-authenticating, the token in the vault will be different or present.
        let current_token = self.vault.get_token(&self.user_id)?;
        let current_count = { *self.reauth_count.read().await };

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

        let reauth_res = tokio::time::timeout(
            std::time::Duration::from_secs(300), // 5 minute timeout for user to login
            auth_manager.reauthenticate(&self.user_id, scopes, None),
        )
        .await;

        match reauth_res {
            Ok(Ok(_)) => {
                {
                    let mut count = self.reauth_count.write().await;
                    *count += 1;
                }
                info!("Re-authentication successful. Deactivating Airlock...");
                let _ = self.suspension_tx.send(false);
                Ok(())
            }
            Ok(Err(e)) => {
                error!("Re-authentication failed: {:?}", e);
                let _ = self.suspension_tx.send(false);
                {
                    let mut last = self.last_reauth.lock().await;
                    *last = None;
                }
                Err(e)
            }
            Err(_) => {
                error!("Re-authentication timed out after 5 minutes.");
                let _ = self.suspension_tx.send(false);
                {
                    let mut last = self.last_reauth.lock().await;
                    *last = None;
                }
                anyhow::bail!("Re-authentication timed out")
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

    /// Handles SSE events from the server and pipes them back to stdio.
    pub async fn listen_sse(
        &self,
        sse_url: &str,
        stdout_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<()> {
        use futures::StreamExt;
        use reqwest_eventsource::EventSource;

        loop {
            self.wait_for_airlock().await?;

            let token_opt = self.vault.get_token(&self.user_id)?;
            let token_for_trigger = token_opt.clone();

            let mut request = if let Some(token) = token_opt.as_ref() {
                let dpop_key = match self.vault.get_dpop_key(&self.user_id)? {
                    Some(bytes) => DpopKey::from_bytes(&bytes)?,
                    None => {
                        info!("No DPoP key found for user in SSE listener, triggering re-authentication...");
                        self.trigger_reauth(None, None, None).await?;
                        continue;
                    }
                };

                let dpop_proof = dpop_key.generate_proof_with_ath("GET", sse_url, Some(token))?;

                let auth_header = match self.auth_scheme {
                    AuthScheme::Bearer => format!("Bearer {}", token),
                    AuthScheme::Dpop => format!("DPoP {}", token),
                };

                self.http_client
                    .get(sse_url)
                    .header("Authorization", auth_header)
                    .header("DPoP", dpop_proof)
                    .header("MCP-Protocol-Version", &self.protocol_version)
            } else {
                info!("No token found for user in SSE listener, sending unauthenticated request to trigger discovery...");
                self.http_client
                    .get(sse_url)
                    .header("MCP-Protocol-Version", &self.protocol_version)
            };

            let sid = {
                let sid_lock = self.session_id.lock().await;
                sid_lock.clone()
            };

            if let Some(s) = sid {
                request = request.header("MCP-Session-Id", s);
            }

            info!("Opening SSE connection to {}...", sse_url);
            let mut source = EventSource::new(request)?;

            while let Some(event) = source.next().await {
                match event {
                    Ok(reqwest_eventsource::Event::Message(message)) => {
                        tracing::debug!(data = %message.data, "Received SSE message");
                        let _ = stdout_tx.send(message.data).await;
                    }
                    Ok(reqwest_eventsource::Event::Open) => info!("SSE connection established"),
                    Err(reqwest_eventsource::Error::InvalidStatusCode(status, resp)) => {
                        if status.as_u16() == 401 {
                            warn!("401 Unauthorized received in SSE listener ({}). Triggering re-authentication...", sse_url);
                            source.close();

                            let challenge = WwwAuthenticate::parse(resp.headers());
                            let metadata_url = challenge.resource_metadata.or_else(|| {
                                Url::parse(&self.remote_url).ok().and_then(|u| {
                                    u.join("/.well-known/oauth-protected-resource")
                                        .ok()
                                        .map(|url| url.to_string())
                                })
                            });

                            if let Err(e) = self
                                .trigger_reauth(
                                    token_for_trigger.as_deref(),
                                    metadata_url.as_deref(),
                                    challenge.scope,
                                )
                                .await
                            {
                                error!("Re-authentication flow failed in SSE listener: {:?}. Retrying connection in 5s...", e);
                            }
                            break;
                        } else {
                            error!(
                                "SSE error: Invalid status code {} from {}. Response: {:?}",
                                status, sse_url, resp
                            );
                            source.close();
                            break;
                        }
                    }
                    Err(e) => {
                        error!("SSE error connecting to {}: {:?}", sse_url, e);
                        source.close();
                        break;
                    }
                }
            }

            warn!("SSE connection lost, retrying in 5 seconds...");
            let jitter = rand::random::<u64>() % 2000;
            tokio::time::sleep(std::time::Duration::from_millis(5000 + jitter)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};

    #[test]
    fn test_www_authenticate_parse_quoted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "DPoP resource_metadata=\"http://example.com/.well-known/oauth-protected-resource\", scope=\"mcp:all\"",
            ),
        );
        let challenge = WwwAuthenticate::parse(&headers);
        assert_eq!(
            challenge.resource_metadata,
            Some("http://example.com/.well-known/oauth-protected-resource".to_string())
        );
        assert_eq!(challenge.scope, Some(vec!["mcp:all".to_string()]));
    }

    #[test]
    fn test_www_authenticate_parse_unquoted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static(
                "DPoP resource_metadata=http://example.com/.well-known/oauth-protected-resource, scope=mcp:all",
            ),
        );
        let challenge = WwwAuthenticate::parse(&headers);
        assert_eq!(
            challenge.resource_metadata,
            Some("http://example.com/.well-known/oauth-protected-resource".to_string())
        );
        assert_eq!(challenge.scope, Some(vec!["mcp:all".to_string()]));
    }

    #[test]
    fn test_url_joining_behavior() {
        let remote_url = "http://localhost:8081/rpc";
        let u = Url::parse(remote_url).unwrap();
        let joined = u.join("/.well-known/oauth-protected-resource").unwrap();
        assert_eq!(
            joined.as_str(),
            "http://localhost:8081/.well-known/oauth-protected-resource"
        );

        let remote_url_no_path = "http://localhost:8081";
        let u = Url::parse(remote_url_no_path).unwrap();
        let joined = u.join("/.well-known/oauth-protected-resource").unwrap();
        assert_eq!(
            joined.as_str(),
            "http://localhost:8081/.well-known/oauth-protected-resource"
        );
    }
}
