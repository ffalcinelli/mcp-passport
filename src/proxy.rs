use crate::Result;
use crate::crypto::DpopKey;
use crate::vault::Vault;
use crate::auth::AuthManager;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tracing::{info, warn, error};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use anyhow::Context;

pub struct Proxy {
    http_client: Client,
    remote_url: String,
    suspension_rx: watch::Receiver<bool>,
    suspension_tx: watch::Sender<bool>,
    vault: Vault,
    user_id: String,
    auth_manager: Arc<AuthManager>,
    protocol_version: String,
    session_id: Mutex<Option<String>>,
    reauth_mutex: Mutex<()>,
    last_reauth: Mutex<Option<std::time::Instant>>,
}

impl Proxy {
    pub fn new(
        remote_url: &str,
        user_id: &str,
        auth_manager: Arc<AuthManager>,
        service: &str,
        protocol_version: &str,
    ) -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            http_client: Client::new(),
            remote_url: remote_url.to_string(),
            suspension_rx: rx,
            suspension_tx: tx,
            vault: Vault::new(service),
            user_id: user_id.to_string(),
            auth_manager,
            protocol_version: protocol_version.to_string(),
            session_id: Mutex::new(None),
            reauth_mutex: Mutex::new(()),
            last_reauth: Mutex::new(None),
        }
    }

    /// Primary entry point for stdio -> HTTP bridge
    pub async fn handle_request(self: Arc<Self>, payload: Value) -> Result<Value> {
        self.wait_for_airlock().await?;

        let token = match self.vault.get_token(&self.user_id)? {
            Some(t) => t,
            None => {
                info!("No token found for user, triggering re-authentication...");
                self.trigger_reauth(None).await?;
                return Box::pin(self.clone().handle_request(payload)).await;
            }
        };
        
        let dpop_key = match self.vault.get_dpop_key(&self.user_id)? {
            Some(bytes) => DpopKey::from_bytes(&bytes)?,
            None => {
                info!("No DPoP key found for user, triggering re-authentication...");
                self.trigger_reauth(None).await?;
                return Box::pin(self.clone().handle_request(payload)).await;
            }
        };
        
        let dpop_proof = dpop_key.generate_proof_with_ath("POST", &self.remote_url, Some(&token))?;

        let mut request = self.http_client
            .post(&self.remote_url)
            .header("Authorization", format!("DPoP {}", token))
            .header("DPoP", dpop_proof)
            .header("MCP-Protocol-Version", &self.protocol_version);

        let sid = {
            let sid_lock = self.session_id.lock().await;
            sid_lock.clone()
        };
        
        if let Some(s) = sid {
            request = request.header("MCP-Session-Id", s);
        }

        let response = request.json(&payload).send().await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            warn!("401 Unauthorized received. Activating Airlock suspension...");
            self.trigger_reauth(Some(&token)).await?;

            // Retry the request after re-authentication
            return Box::pin(self.clone().handle_request(payload)).await;
        }

        // Capture Session ID if returned
        if let Some(sid) = response.headers().get("mcp-session-id").and_then(|h| h.to_str().ok()) {
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
        Ok(body)
    }

    async fn trigger_reauth(&self, failing_token: Option<&str>) -> Result<()> {
        let _guard = self.reauth_mutex.lock().await;
        
        // If airlock is already active, someone else is handling it.
        // Wait for it to clear and then return.
        if *self.suspension_rx.borrow() {
            info!("Airlock already active, waiting for it to clear...");
            drop(_guard); // Release lock while waiting for airlock
            self.wait_for_airlock().await?;
            return Ok(());
        }

        // Circuit Breaker: prevent rapid consecutive re-authentications
        let now = std::time::Instant::now();
        {
            let mut last = self.last_reauth.lock().await;
            if let Some(t) = *last {
                if now.duration_since(t) < std::time::Duration::from_secs(10) {
                    error!("Authentication loop detected. Re-authentication triggered too frequently (within 10s).");
                    return Err(anyhow::anyhow!("Authentication loop detected. Please check your credentials and environment configuration."));
                }
            }
            *last = Some(now);
        }

        // Re-check if re-authentication is still needed after acquiring the lock.
        // If another task just finished re-authenticating, the token in the vault will be different or present.
        let current_token = self.vault.get_token(&self.user_id)?;
        if let (Some(failing), Some(current)) = (failing_token, current_token.as_deref()) {
            if failing != current {
                info!("Token has already been updated by another task. Skipping redundant re-auth.");
                return Ok(());
            }
        } else if failing_token.is_none() && current_token.is_some() {
            info!("Token was missing but is now present. Skipping redundant re-auth.");
            return Ok(());
        }

        let _ = self.suspension_tx.send(true);
        info!("Airlock activated. Performing re-authentication...");
        
        // Clear invalid token from vault to avoid re-using it
        let _ = self.vault.delete_token(&self.user_id);

        if let Err(e) = self.auth_manager.reauthenticate(&self.user_id, None).await {
            error!("Re-authentication failed: {:?}", e);
            let _ = self.suspension_tx.send(false);
            return Err(e);
        }
        
        info!("Re-authentication successful. Deactivating Airlock...");
        let _ = self.suspension_tx.send(false);
        Ok(())
    }

    async fn wait_for_airlock(&self) -> Result<()> {
        let mut rx = self.suspension_rx.clone();
        while *rx.borrow() {
            rx.changed().await.context("Suspension channel closed")?;
        }
        Ok(())
    }

    /// Handles SSE events from the server and pipes them back to stdio
    pub async fn listen_sse(&self, sse_url: &str, stdout_tx: tokio::sync::mpsc::Sender<String>) -> Result<()> {
        use reqwest_eventsource::EventSource;
        use futures::StreamExt;

        loop {
            self.wait_for_airlock().await?;

            let token = match self.vault.get_token(&self.user_id)? {
                Some(t) => t,
                None => {
                    info!("No token found for user in SSE listener, triggering re-authentication...");
                    self.trigger_reauth(None).await?;
                    continue;
                }
            };
            let dpop_key = match self.vault.get_dpop_key(&self.user_id)? {
                Some(bytes) => DpopKey::from_bytes(&bytes)?,
                None => {
                    info!("No DPoP key found for user in SSE listener, triggering re-authentication...");
                    self.trigger_reauth(None).await?;
                    continue;
                }
            };

            let dpop_proof = dpop_key.generate_proof_with_ath("GET", sse_url, Some(&token))?;

            let mut request = self.http_client.get(sse_url)
                .header("Authorization", format!("DPoP {}", token))
                .header("DPoP", dpop_proof)
                .header("MCP-Protocol-Version", &self.protocol_version);

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
                info!("SSE event received");
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
                            self.trigger_reauth(Some(&token)).await?;
                            break;
                        } else {
                            error!("SSE error: Invalid status code {} from {}. Response: {:?}", status, sse_url, resp);
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
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}
