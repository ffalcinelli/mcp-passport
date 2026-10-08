//! # OIDC/OAuth2 Authentication Manager
//!
//! This module implements the OpenID Connect (OIDC) flow with FAPI 2.0 security
//! enhancements, including:
//! - **Pushed Authorization Requests (PAR)**
//! - **PKCE** (Proof Key for Code Exchange)
//! - **DPoP** (Demonstrating Proof-of-Possession)
//! - **RFC 8707 Resource Indicators**
//!
//! It also includes a local loopback server to handle the OAuth2 callback.

use crate::crypto::DpopKey;
use crate::discovery;
use crate::net;
use crate::vault::Vault;
use crate::Result;
use anyhow::Context;
use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use colored::Colorize;
use rand_core::{OsRng, RngCore};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

/// Configuration for the OIDC provider and local callback server.
#[derive(Clone)]
pub struct OidcConfig {
    /// URL for OIDC discovery (.well-known/openid-configuration).
    pub discovery_url: Option<String>,
    /// OIDC Client ID.
    pub client_id: String,
    /// URL for the OAuth2 callback (must match provider configuration).
    pub redirect_url: String,
    /// Optional override for the authorization endpoint.
    pub auth_url_override: Option<String>,
    /// Optional override for the token endpoint.
    pub token_url_override: Option<String>,
    /// Optional override for the PAR endpoint.
    pub par_url_override: Option<String>,
    /// Internal channel to communicate the auth URL (used for automation/tests).
    pub internal_url_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<String>>>>,
    /// Internal channel to communicate the callback server address (used for automation/tests).
    pub internal_callback_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<SocketAddr>>>>,
    /// Directory containing custom templates for success/failure pages.
    pub template_dir: Option<std::path::PathBuf>,
    /// Timeouts and retry delays used by the auth flow and the SSE listener.
    pub timeouts: Timeouts,
    /// Accept plain-HTTP authorization server endpoints on non-loopback hosts.
    pub allow_insecure_http: bool,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            discovery_url: None,
            client_id: String::new(),
            redirect_url: String::new(),
            auth_url_override: None,
            token_url_override: None,
            par_url_override: None,
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            template_dir: None,
            timeouts: Timeouts::default(),
            allow_insecure_http: false,
        }
    }
}

/// Timeouts and retry delays. `Default` holds the production values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// How long to wait for the user to complete the browser login.
    pub auth: Duration,
    /// Delay between attempts to bind the loopback callback port.
    pub bind_retry: Duration,
    /// Base delay before reconnecting a dropped SSE stream.
    pub sse_retry_base: Duration,
    /// Maximum random jitter added to `sse_retry_base`.
    pub sse_retry_jitter: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            auth: Duration::from_secs(300),
            bind_retry: Duration::from_secs(1),
            sse_retry_base: Duration::from_secs(5),
            sse_retry_jitter: Duration::from_secs(2),
        }
    }
}

impl Timeouts {
    /// Short timeouts, intended for tests.
    pub fn fast() -> Self {
        Self {
            auth: Duration::from_millis(500),
            bind_retry: Duration::from_millis(10),
            sse_retry_base: Duration::from_millis(10),
            sse_retry_jitter: Duration::from_millis(10),
        }
    }
}

/// Connect timeout for every outbound HTTP connection.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total timeout for requests to the authorization server (discovery, PAR, token).
const AS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("discovery_url", &self.discovery_url)
            .field("client_id", &self.client_id)
            .field("redirect_url", &self.redirect_url)
            .field("template_dir", &self.template_dir)
            .field("timeouts", &self.timeouts)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish()
    }
}

/// Manages OIDC discovery, token exchange, and the DPoP flow.
#[derive(Clone)]
pub struct AuthManager {
    /// OIDC Client ID.
    client_id: String,
    /// URL for the authorization endpoint.
    auth_url: String,
    /// URL for the token endpoint.
    token_url: String,
    /// URL for the PAR endpoint.
    par_url: String,
    /// URL for the OAuth2 callback.
    redirect_url: String,
    /// Resource indicator (MCP server URL).
    resource: String,
    /// HTTP client for OIDC requests.
    http_client: HttpClient,
    /// Secure vault for storing tokens.
    vault: Vault,
    /// Internal channel to communicate the auth URL.
    internal_url_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<String>>>>,
    /// Internal channel to communicate the callback server address.
    internal_callback_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<SocketAddr>>>>,
    /// Success template HTML.
    success_html: Arc<String>,
    /// Failure template HTML.
    failure_html: Arc<String>,
    /// Human-friendly name of the identity provider.
    issuer_name: String,
    /// Human-friendly name of the protected resource.
    resource_name: String,
    /// Timeouts for the interactive flow.
    timeouts: Timeouts,
    /// The authorization server's issuer identifier, when discovered.
    issuer: Option<String>,
    /// Whether the AS always returns `iss` in the authorization response (RFC 9207).
    iss_required: bool,
    /// Latest DPoP nonce provided by the authorization server (RFC 9449 §8).
    as_nonce: Arc<std::sync::Mutex<Option<String>>>,
}

/// Query parameters of the authorization response (RFC 6749 §4.1.2, RFC 9207).
#[derive(Deserialize, Default)]
struct AuthCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    iss: Option<String>,
}

#[derive(Deserialize)]
struct ParResponse {
    request_uri: String,
}

/// Successful token endpoint response (RFC 6749 §5.1).
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
    refresh_token: Option<String>,
}

impl AuthManager {
    /// Resolves the authorization server endpoints for `resource`.
    ///
    /// `resource_metadata_url` is the (already validated) RFC 9728 metadata URL
    /// taken from a `WWW-Authenticate` challenge, if any.
    pub async fn discover(
        mut oidc_config: OidcConfig,
        resource: String,
        vault: Vault,
        resource_metadata_url: Option<&str>,
    ) -> Result<Self> {
        let http_client = HttpClient::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(AS_REQUEST_TIMEOUT)
            .build()
            .context("Failed to build HTTP client")?;

        let overrides_complete = oidc_config.auth_url_override.is_some()
            && oidc_config.token_url_override.is_some()
            && oidc_config.par_url_override.is_some();

        // Precedence: explicit endpoint overrides, then an explicitly configured
        // discovery URL, then dynamic discovery from the resource (RFC 9728).
        let (metadata, mut resource_name) = if overrides_complete {
            (None, None)
        } else if let Some(url) = oidc_config.discovery_url.as_deref() {
            info!("Using configured OIDC discovery URL {}", url);
            net::require_secure_url(url, "OIDC discovery URL", oidc_config.allow_insecure_http)?;
            let metadata = discovery::fetch_configured_metadata(&http_client, url).await?;
            (Some(metadata), None)
        } else {
            info!("Discovering the authorization server for {}...", resource);
            let found = discovery::discover_from_resource(
                &http_client,
                &resource,
                resource_metadata_url,
                oidc_config.allow_insecure_http,
            )
            .await?;
            (Some(found.metadata), found.resource_name)
        };

        let auth_url = oidc_config
            .auth_url_override
            .take()
            .or_else(|| metadata.as_ref().map(|m| m.authorization_endpoint.clone()))
            .context("No authorization endpoint (set --kc-auth-url or a discovery URL)")?;
        let token_url = oidc_config
            .token_url_override
            .take()
            .or_else(|| metadata.as_ref().map(|m| m.token_endpoint.clone()))
            .context("No token endpoint (set --kc-token-url or a discovery URL)")?;
        let par_url = oidc_config
            .par_url_override
            .take()
            .or_else(|| {
                metadata
                    .as_ref()
                    .and_then(|m| m.pushed_authorization_request_endpoint.clone())
            })
            .context(
                "Authorization server metadata has no pushed_authorization_request_endpoint \
                 and no --kc-par-url override was provided",
            )?;
        for (url, what) in [
            (&auth_url, "authorization endpoint"),
            (&token_url, "token endpoint"),
            (&par_url, "PAR endpoint"),
        ] {
            net::require_secure_url(url, what, oidc_config.allow_insecure_http)?;
        }

        let issuer = metadata.as_ref().map(|m| m.issuer.clone());
        let iss_required = metadata
            .as_ref()
            .is_some_and(|m| m.authorization_response_iss_parameter_supported);
        let issuer_name = metadata
            .map(|m| m.organization_name.unwrap_or(m.issuer))
            .unwrap_or_else(|| "Custom Provider".to_string());

        if resource_name.is_none() {
            resource_name = discovery::fetch_resource_name(&http_client, &resource).await;
        }
        let resource_name = resource_name.unwrap_or_else(|| resource.clone());

        let (success_html, failure_html) = if let Some(dir) = &oidc_config.template_dir {
            let (success_res, failure_res) = tokio::join!(
                tokio::fs::read_to_string(dir.join("success.html")),
                tokio::fs::read_to_string(dir.join("failure.html"))
            );
            (
                success_res.unwrap_or_else(|_| crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
                failure_res.unwrap_or_else(|_| crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            )
        } else {
            (
                crate::templates::DEFAULT_SUCCESS_HTML.to_string(),
                crate::templates::DEFAULT_FAILURE_HTML.to_string(),
            )
        };

        Ok(Self {
            client_id: oidc_config.client_id,
            auth_url,
            token_url,
            par_url,
            redirect_url: oidc_config.redirect_url,
            resource,
            http_client,
            vault,
            internal_url_tx: oidc_config.internal_url_tx,
            internal_callback_tx: oidc_config.internal_callback_tx,
            success_html: Arc::new(success_html),
            failure_html: Arc::new(failure_html),
            issuer_name,
            resource_name,
            timeouts: oidc_config.timeouts,
            issuer,
            iss_required,
            as_nonce: Arc::default(),
        })
    }

    pub async fn set_internal_url_tx(&self, tx: oneshot::Sender<String>) {
        let mut lock = self.internal_url_tx.lock().await;
        *lock = Some(tx);
    }

    pub async fn set_internal_callback_tx(&self, tx: oneshot::Sender<SocketAddr>) {
        let mut lock = self.internal_callback_tx.lock().await;
        *lock = Some(tx);
    }

    /// Full re-authentication flow: PAR -> Loopback Callback -> Token Exchange
    pub async fn reauthenticate(
        &self,
        user_id: &str,
        scopes: Option<Vec<String>>,
        url_tx: Option<oneshot::Sender<String>>,
    ) -> Result<()> {
        info!(
            "Starting FAPI 2.0 re-authentication flow for user '{}'...",
            user_id
        );

        // 1. Generate a new ephemeral DPoP key. It is only stored once the token
        // exchange succeeds, so a failed flow leaves the current credentials intact.
        let dpop_key = DpopKey::generate();

        // 2. Prepare PKCE and State
        let pkce_verifier = random_urlsafe(32);
        let pkce_challenge = pkce_s256_challenge(&pkce_verifier);
        let state_val = random_urlsafe(16);

        // 3. Setup Loopback Server to catch the callback
        let expected_state = state_val.clone();
        let (server_handle, rx) = self.setup_loopback_server(expected_state).await?;

        // 4. Pushed Authorization Request (PAR)
        let par_data = self
            .perform_par_request(&pkce_challenge, &state_val, scopes, &server_handle)
            .await?;

        // 5. Direct user to Auth URL
        if let Err(e) = self.open_auth_url(&par_data, url_tx).await {
            server_handle.abort();
            return Err(e);
        }

        // 6. Wait for code from callback
        let callback = tokio::time::timeout(self.timeouts.auth, rx).await;
        server_handle.abort();
        let code = match callback {
            Ok(Ok(Ok(code))) => code,
            Ok(Ok(Err(reason))) => anyhow::bail!("Authorization failed: {}", reason),
            _ => anyhow::bail!("Authentication timed out or failed to receive callback"),
        };

        // 7. Token Exchange with DPoP
        info!("Step 2: Exchanging code for DPoP-bound token...");
        self.manual_token_exchange(user_id, &code, &pkce_verifier, &dpop_key)
            .await?;

        Ok(())
    }

    async fn setup_loopback_server(
        &self,
        expected_state: String,
    ) -> Result<(
        tokio::task::JoinHandle<()>,
        oneshot::Receiver<CallbackResult>,
    )> {
        let redirect = net::require_loopback_redirect(&self.redirect_url)?;
        let (tx, rx) = oneshot::channel::<CallbackResult>();
        let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

        let app = Router::new()
            .route("/callback", get(handle_callback))
            .with_state(AuthServerState {
                expected_state,
                tx,
                success_html: self.success_html.clone(),
                failure_html: self.failure_html.clone(),
                issuer_name: self.issuer_name.clone(),
                resource_name: self.resource_name.clone(),
                expected_issuer: self.issuer.clone(),
                iss_required: self.iss_required,
            });

        let addr: SocketAddr = redirect
            .socket_addrs(|| None)?
            .first()
            .copied()
            .context("Failed to parse redirect URL into socket address")?;

        let mut listener = None;
        for i in 0..5 {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => {
                    listener = Some(l);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    if i == 4 {
                        return Err(anyhow::anyhow!(e).context(format!("Failed to bind to {} after 5 retries. Someone else is using this port.", addr)));
                    }
                    warn!(
                        "Address {} already in use, retrying... (attempt {})",
                        addr,
                        i + 1
                    );
                    tokio::time::sleep(self.timeouts.bind_retry).await;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let listener = listener.context("Failed to bind loopback listener after retries")?;
        let local_addr = listener.local_addr()?;

        // Notify of bound address if requested (for tests)
        {
            let mut lock = self.internal_callback_tx.lock().await;
            if let Some(tx_addr) = lock.take() {
                let _ = tx_addr.send(local_addr);
            }
        }

        let server_handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Loopback server error: {:?}", e);
            }
        });

        Ok((server_handle, rx))
    }

    async fn perform_par_request(
        &self,
        pkce_challenge: &str,
        state_val: &str,
        scopes: Option<Vec<String>>,
        server_handle: &tokio::task::JoinHandle<()>,
    ) -> Result<ParResponse> {
        info!("Step 1: Pushed Authorization Request (PAR)...");
        let mut par_params = vec![
            ("client_id", self.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", self.redirect_url.as_str()),
            ("code_challenge", pkce_challenge),
            ("code_challenge_method", "S256"),
            ("state", state_val),
            ("resource", self.resource.as_str()),
        ];

        let mut s_vec = scopes.unwrap_or_default();
        if !s_vec.iter().any(|s| s == "openid") {
            s_vec.push("openid".to_string());
        }
        let scope_str = s_vec.join(" ");
        par_params.push(("scope", &scope_str));

        let par_res = self
            .http_client
            .post(&self.par_url)
            .form(&par_params)
            .send()
            .await?;

        if !par_res.status().is_success() {
            let error_text = par_res.text().await?;
            error!("PAR request failed: {}", error_text);
            server_handle.abort();
            anyhow::bail!("PAR request failed: {}", error_text);
        }

        let par_data: ParResponse = par_res.json().await?;
        Ok(par_data)
    }

    async fn open_auth_url(
        &self,
        par_data: &ParResponse,
        url_tx: Option<oneshot::Sender<String>>,
    ) -> Result<()> {
        let auth_url = build_authorize_url(&self.auth_url, &self.client_id, &par_data.request_uri)?;

        eprintln!(
            "{}",
            "****************************************************************".yellow()
        );
        eprintln!(
            "{}",
            "🔐 ACTION REQUIRED: Please visit the following URL to authenticate:"
                .bold()
                .yellow()
        );
        eprintln!("{}", auth_url.bold().cyan());
        eprintln!(
            "{}",
            "****************************************************************".yellow()
        );

        // Attempt to open the browser automatically (skip if in tests or explicitly requested)
        let skip_open = std::env::var("MCP_PASSPORT_SKIP_OPEN_BROWSER").is_ok();
        let mut has_listener = url_tx.is_some();

        if !has_listener {
            let lock = self.internal_url_tx.lock().await;
            has_listener = lock.is_some();
        }

        if !skip_open && !has_listener {
            let is_safe_url = url::Url::parse(&auth_url)
                .is_ok_and(|u| u.scheme() == "http" || u.scheme() == "https");

            if is_safe_url {
                if let Err(e) = open::that(&auth_url) {
                    warn!(
                        "Failed to open browser automatically: {}. Please copy the URL above.",
                        e
                    );
                }
            } else {
                warn!("Skipping automatic browser open: URL scheme is not http or https. Please copy the URL above.");
            }
        } else {
            info!("Skipping automatic browser open (internal listener or skip flag present).");
        }

        // Send the URL to a possible listener (for tests)
        if let Some(tx_url) = url_tx {
            let _ = tx_url.send(auth_url.clone());
        } else {
            let mut lock = self.internal_url_tx.lock().await;
            if let Some(tx_url) = lock.take() {
                let _ = tx_url.send(auth_url.clone());
            }
        }
        Ok(())
    }

    /// Exchanges the authorization code for a DPoP-bound token and stores it,
    /// together with its key and refresh token.
    async fn manual_token_exchange(
        &self,
        user_id: &str,
        code: &str,
        pkce_verifier: &str,
        dpop_key: &DpopKey,
    ) -> Result<()> {
        let params = [
            ("grant_type", "authorization_code"),
            ("client_id", self.client_id.as_str()),
            ("code", code),
            ("redirect_uri", self.redirect_url.as_str()),
            ("code_verifier", pkce_verifier),
            ("resource", self.resource.as_str()),
        ];
        let tokens = self
            .token_request(&params, dpop_key)
            .await?
            .map_err(|err| anyhow::anyhow!("Token exchange failed: {}", err))?;

        self.vault.store_dpop_key(user_id, &dpop_key.to_bytes())?;
        self.store_tokens(user_id, &tokens)?;
        if tokens.refresh_token.is_none() {
            // A refresh token we still hold is bound to the previous key.
            self.vault.delete_refresh_token(user_id)?;
        }
        info!("Successfully acquired and stored DPoP-bound token.");
        Ok(())
    }

    /// Renews the access token with the stored refresh token (RFC 6749 §6),
    /// without user interaction.
    ///
    /// Returns `Ok(false)` when there is nothing to refresh with or the
    /// authorization server rejects the refresh token (which is then deleted),
    /// so the caller can fall back to the interactive flow.
    pub async fn refresh(&self, user_id: &str) -> Result<bool> {
        let Some(refresh_token) = self.vault.get_refresh_token(user_id)? else {
            return Ok(false);
        };
        // Refresh tokens of public clients are bound to the DPoP key (RFC 9449 §5).
        let Some(key_bytes) = self.vault.get_dpop_key(user_id)? else {
            self.vault.delete_refresh_token(user_id)?;
            return Ok(false);
        };
        let dpop_key = DpopKey::from_bytes(&key_bytes)?;

        info!("Refreshing the access token...");
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", self.client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
            ("resource", self.resource.as_str()),
        ];
        match self.token_request(&params, &dpop_key).await? {
            Ok(tokens) => {
                self.store_tokens(user_id, &tokens)?;
                info!("Access token refreshed.");
                Ok(true)
            }
            Err(err) => {
                warn!("Refresh token rejected ({}); a new login is needed.", err);
                self.vault.delete_refresh_token(user_id)?;
                Ok(false)
            }
        }
    }

    /// POSTs to the token endpoint with a DPoP proof. The outer error is a
    /// transport failure; the inner one is the endpoint's error response.
    ///
    /// If the AS demands a DPoP nonce (`use_dpop_nonce`), the request is
    /// retried once with the nonce it supplied (RFC 9449 §8).
    async fn token_request(
        &self,
        params: &[(&str, &str)],
        dpop_key: &DpopKey,
    ) -> Result<std::result::Result<TokenResponse, String>> {
        let mut retried = false;
        let res = loop {
            let nonce = self.as_nonce.lock().ok().and_then(|n| n.clone());
            let dpop_proof = dpop_key.generate_proof_with_ath(
                "POST",
                &self.token_url,
                None,
                nonce.as_deref(),
            )?;
            let res = self
                .http_client
                .post(&self.token_url)
                .header("DPoP", dpop_proof)
                .form(params)
                .send()
                .await?;
            let new_nonce = crate::crypto::dpop_nonce(res.headers());
            if let Some(n) = &new_nonce {
                if let Ok(mut slot) = self.as_nonce.lock() {
                    *slot = Some(n.clone());
                }
            }
            if res.status().is_success() {
                break res;
            }

            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            let wants_nonce = status == reqwest::StatusCode::BAD_REQUEST
                && serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                    .as_deref()
                    == Some("use_dpop_nonce");
            if wants_nonce && new_nonce.is_some() && !retried {
                info!("Authorization server requires a DPoP nonce; retrying.");
                retried = true;
                continue;
            }
            error!("Token endpoint returned {}: {}", status, body);
            return Ok(Err(format!("{status}: {body}")));
        };

        let tokens: TokenResponse = res.json().await.context("Invalid token response")?;
        match tokens.token_type.as_deref() {
            Some(t) if t.eq_ignore_ascii_case("DPoP") => {}
            other => warn!(
                "Token endpoint returned token_type {:?} instead of \"DPoP\": the token is not \
                 bound to the DPoP key (RFC 9449 §5).",
                other
            ),
        }
        Ok(Ok(tokens))
    }

    fn store_tokens(&self, user_id: &str, tokens: &TokenResponse) -> Result<()> {
        self.vault.store_token(user_id, &tokens.access_token)?;
        // A refresh response without refresh_token keeps the current one (RFC 6749 §6).
        if let Some(refresh) = &tokens.refresh_token {
            self.vault.store_refresh_token(user_id, refresh)?;
        }
        Ok(())
    }

    /// Retrieves the current access token for a user from the vault.
    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        self.vault.get_token(user_id)
    }
}

/// What the loopback callback delivers: the authorization code, or why it failed.
type CallbackResult = std::result::Result<String, String>;

#[derive(Clone)]
struct AuthServerState {
    expected_state: String,
    tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<CallbackResult>>>>,
    success_html: Arc<String>,
    failure_html: Arc<String>,
    issuer_name: String,
    resource_name: String,
    /// Issuer the `iss` response parameter must match (RFC 9207).
    expected_issuer: Option<String>,
    /// Reject responses without `iss` (the AS advertised support for it).
    iss_required: bool,
}

/// Checks an authorization response whose `state` already matched.
fn evaluate_callback(query: &AuthCallback, state: &AuthServerState) -> CallbackResult {
    // RFC 9207: a mismatching `iss` means the response comes from another AS
    // (mix-up attack), so it is checked before anything else is trusted.
    match (&query.iss, &state.expected_issuer) {
        (Some(iss), Some(expected)) if iss != expected => {
            return Err(format!(
                "issuer mismatch in authorization response ('{iss}', expected '{expected}')"
            ));
        }
        (None, Some(_)) if state.iss_required => {
            return Err("authorization response is missing the 'iss' parameter".into());
        }
        _ => {}
    }
    if let Some(error) = &query.error {
        return Err(match &query.error_description {
            Some(desc) => format!("{error}: {desc}"),
            None => error.clone(),
        });
    }
    query
        .code
        .clone()
        .ok_or_else(|| "authorization response has no code".to_string())
}

async fn handle_callback(
    query: Query<AuthCallback>,
    State(state): State<AuthServerState>,
) -> impl IntoResponse {
    let render_failure = |status: axum::http::StatusCode, message: &str| {
        let html = render_template(
            &state.failure_html,
            Some(message),
            &state.issuer_name,
            &state.resource_name,
        );
        (status, axum::response::Html(html)).into_response()
    };

    // Requests without the right state are not ours: ignore them without
    // ending the flow, so a stray page can't cancel the login.
    if query.state.as_deref() != Some(state.expected_state.as_str()) {
        return render_failure(axum::http::StatusCode::BAD_REQUEST, "Invalid state");
    }

    let Some(sender) = state.tx.lock().await.take() else {
        return render_failure(
            axum::http::StatusCode::GONE,
            "Already authenticated or timed out.",
        );
    };

    let result = evaluate_callback(&query, &state);
    let outcome = match &result {
        Ok(_) => None,
        Err(reason) => Some(format!("Authorization failed: {reason}")),
    };
    let _ = sender.send(result);

    match outcome {
        None => {
            let html = render_template(
                &state.success_html,
                None,
                &state.issuer_name,
                &state.resource_name,
            );
            (axum::http::StatusCode::OK, axum::response::Html(html)).into_response()
        }
        Some(message) => render_failure(axum::http::StatusCode::BAD_REQUEST, &message),
    }
}

fn escape_html(s: &str) -> String {
    html_escape::encode_safe(s).to_string()
}

fn render_template(
    template: &str,
    error_message: Option<&str>,
    issuer_name: &str,
    resource_name: &str,
) -> String {
    let mut result = template.replace("{{ISSUER_NAME}}", &escape_html(issuer_name));
    result = result.replace("{{RESOURCE_NAME}}", &escape_html(resource_name));
    if let Some(msg) = error_message {
        result = result.replace("{{ERROR_MESSAGE}}", &escape_html(msg));
    }
    result
}

/// Builds the authorization URL for a PAR `request_uri` (RFC 9126 §4),
/// keeping any query the endpoint already has.
fn build_authorize_url(auth_endpoint: &str, client_id: &str, request_uri: &str) -> Result<String> {
    let mut url = url::Url::parse(auth_endpoint)
        .with_context(|| format!("Invalid authorization endpoint '{auth_endpoint}'"))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("request_uri", request_uri);
    Ok(url.into())
}

/// Returns `len` bytes from the OS CSPRNG, base64url-encoded without padding.
fn random_urlsafe(len: usize) -> String {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// PKCE S256 code challenge (RFC 7636 §4.2).
fn pkce_s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_authorize_url_encodes_and_keeps_query() {
        let url = build_authorize_url(
            "https://as.example.com/authorize?tenant=a",
            "my client&x=1",
            "urn:ietf:params:oauth:request_uri:abc",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://as.example.com/authorize?tenant=a&client_id=my+client%26x%3D1\
             &response_type=code&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"
        );
        assert!(build_authorize_url("not a url", "c", "r").is_err());
    }

    #[test]
    fn test_pkce_s256_challenge() {
        // RFC 7636 Appendix B test vector
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn test_random_urlsafe() {
        let a = random_urlsafe(32);
        assert_eq!(a.len(), 43); // RFC 7636 verifier length for 32 bytes
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(a, random_urlsafe(32));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(
            escape_html("\"double quotes\""),
            "&quot;double quotes&quot;"
        );
        assert_eq!(escape_html("'single quotes'"), "&#x27;single quotes&#x27;");
        assert_eq!(
            escape_html("<img src=x onerror=alert(1)>"),
            "&lt;img src=x onerror=alert(1)&gt;"
        );
    }

    #[tokio::test]
    async fn test_auth_manager_set_internal_callback_tx() {
        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "a".into(),
            token_url: "t".into(),
            par_url: "p".into(),
            redirect_url: "r".into(),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc_test_set_internal_callback_tx"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };

        let (tx, _rx) = oneshot::channel::<SocketAddr>();
        am.set_internal_callback_tx(tx).await;

        let lock = am.internal_callback_tx.lock().await;
        assert!(lock.is_some());
    }

    #[tokio::test]
    async fn test_handle_callback_success() {
        let (tx, mut rx) = oneshot::channel::<CallbackResult>();
        let state = AuthServerState {
            expected_state: "test_state".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            issuer_name: "Test Issuer".to_string(),
            resource_name: "Test Resource".to_string(),
            expected_issuer: None,
            iss_required: false,
        };

        let query = Query(AuthCallback {
            code: Some("test_code".into()),
            state: Some("test_state".into()),
            ..Default::default()
        });

        let response = handle_callback(query, State(state)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(rx.try_recv().unwrap(), Ok("test_code".to_string()));
    }

    #[tokio::test]
    async fn test_handle_callback_with_templates() -> Result<()> {
        let temp_dir = std::env::temp_dir().join(format!("mcp_test_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await?;
        tokio::fs::write(temp_dir.join("success.html"), "SUCCESS {{RESOURCE_NAME}}").await?;
        tokio::fs::write(temp_dir.join("failure.html"), "FAILURE {{ERROR_MESSAGE}}").await?;

        let (tx, mut rx) = oneshot::channel::<CallbackResult>();
        let state = AuthServerState {
            expected_state: "test_state".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            success_html: std::sync::Arc::new(
                tokio::fs::read_to_string(temp_dir.join("success.html"))
                    .await
                    .unwrap(),
            ),
            failure_html: std::sync::Arc::new(
                tokio::fs::read_to_string(temp_dir.join("failure.html"))
                    .await
                    .unwrap(),
            ),
            issuer_name: "Test Issuer".to_string(),
            resource_name: "Test Resource".to_string(),
            expected_issuer: None,
            iss_required: false,
        };

        // 1. Success case
        let query_ok = Query(AuthCallback {
            code: Some("test_code".into()),
            state: Some("test_state".into()),
            ..Default::default()
        });
        let res_ok = handle_callback(query_ok, State(state.clone()))
            .await
            .into_response();
        assert_eq!(res_ok.status(), axum::http::StatusCode::OK);
        let body_ok = axum::body::to_bytes(res_ok.into_body(), 1024)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body_ok).contains("SUCCESS Test Resource"));
        assert_eq!(rx.try_recv().unwrap(), Ok("test_code".to_string()));

        // 2. Invalid state case
        let query_err = Query(AuthCallback {
            code: Some("c".into()),
            state: Some("wrong".into()),
            ..Default::default()
        });
        let res_err = handle_callback(query_err, State(state.clone()))
            .await
            .into_response();
        assert_eq!(res_err.status(), axum::http::StatusCode::BAD_REQUEST);
        let body_err = axum::body::to_bytes(res_err.into_body(), 1024)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body_err).contains("FAILURE Invalid state"));

        // 3. Already authenticated case (tx taken)
        let query_gone = Query(AuthCallback {
            code: Some("c".into()),
            state: Some("test_state".into()),
            ..Default::default()
        });
        let res_gone = handle_callback(query_gone, State(state.clone()))
            .await
            .into_response();
        assert_eq!(res_gone.status(), axum::http::StatusCode::GONE);
        let body_gone = axum::body::to_bytes(res_gone.into_body(), 1024)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body_gone).contains("FAILURE Already authenticated"));

        tokio::fs::remove_dir_all(temp_dir).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_callback_invalid_state() {
        let (tx, _rx) = oneshot::channel::<CallbackResult>();
        let state = AuthServerState {
            expected_state: "expected".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            issuer_name: "Test Issuer".to_string(),
            resource_name: "Test Resource".to_string(),
            expected_issuer: None,
            iss_required: false,
        };

        let query = Query(AuthCallback {
            code: Some("code".into()),
            state: Some("wrong".into()),
            ..Default::default()
        });

        let response = handle_callback(query, State(state)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_handle_callback_xss_prevention() -> Result<()> {
        let (tx, _rx) = oneshot::channel::<CallbackResult>();
        let state = AuthServerState {
            expected_state: "test_state".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            issuer_name: "<script>alert('xss')</script>".to_string(),
            resource_name: "<b>Bold Resource</b>".to_string(),
            expected_issuer: None,
            iss_required: false,
        };

        // 1. Invalid state case (triggering failure template)
        let query_err = Query(AuthCallback {
            code: Some("c".into()),
            state: Some("wrong".into()),
            ..Default::default()
        });
        let res_err = handle_callback(query_err, State(state.clone()))
            .await
            .into_response();
        let body_err = axum::body::to_bytes(res_err.into_body(), 4096)
            .await
            .unwrap();
        let html_err = String::from_utf8_lossy(&body_err);

        assert!(html_err.contains("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;"));
        assert!(html_err.contains("&lt;b&gt;Bold Resource&lt;&#x2F;b&gt;"));
        assert!(!html_err.contains("<script>"));
        assert!(!html_err.contains("<b>"));

        Ok(())
    }

    fn callback_state(
        tx: oneshot::Sender<CallbackResult>,
        expected_issuer: Option<&str>,
        iss_required: bool,
    ) -> AuthServerState {
        AuthServerState {
            expected_state: "st".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            success_html: Arc::new("OK".to_string()),
            failure_html: Arc::new("FAIL {{ERROR_MESSAGE}}".to_string()),
            issuer_name: "Issuer".to_string(),
            resource_name: "Resource".to_string(),
            expected_issuer: expected_issuer.map(str::to_string),
            iss_required,
        }
    }

    async fn body_of(res: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[tokio::test]
    async fn test_handle_callback_error_fails_flow_immediately() {
        let (tx, mut rx) = oneshot::channel::<CallbackResult>();
        let query = Query(AuthCallback {
            state: Some("st".into()),
            error: Some("access_denied".into()),
            error_description: Some("User <denied>".into()),
            ..Default::default()
        });
        let res = handle_callback(query, State(callback_state(tx, None, false)))
            .await
            .into_response();
        assert_eq!(res.status(), axum::http::StatusCode::BAD_REQUEST);
        assert!(body_of(res)
            .await
            .contains("access_denied: User &lt;denied&gt;"));
        assert_eq!(
            rx.try_recv().unwrap(),
            Err("access_denied: User <denied>".to_string())
        );
    }

    #[tokio::test]
    async fn test_handle_callback_error_with_wrong_state_is_ignored() {
        let (tx, mut rx) = oneshot::channel::<CallbackResult>();
        let query = Query(AuthCallback {
            state: Some("other".into()),
            error: Some("access_denied".into()),
            ..Default::default()
        });
        let res = handle_callback(query, State(callback_state(tx, None, false)))
            .await
            .into_response();
        assert_eq!(res.status(), axum::http::StatusCode::BAD_REQUEST);
        // The flow is still waiting for the real response.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_callback_missing_state_is_ignored() {
        let (tx, mut rx) = oneshot::channel::<CallbackResult>();
        let query = Query(AuthCallback {
            code: Some("c".into()),
            ..Default::default()
        });
        let res = handle_callback(query, State(callback_state(tx, None, false)))
            .await
            .into_response();
        assert_eq!(res.status(), axum::http::StatusCode::BAD_REQUEST);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_evaluate_callback_issuer_checks() {
        let ok = |iss: Option<&str>, expected: Option<&str>, required: bool| {
            let (tx, _rx) = oneshot::channel::<CallbackResult>();
            let query = AuthCallback {
                code: Some("c".into()),
                state: Some("st".into()),
                iss: iss.map(str::to_string),
                ..Default::default()
            };
            evaluate_callback(&query, &callback_state(tx, expected, required))
        };
        let issuer = Some("https://as.example.com");
        assert_eq!(ok(issuer, issuer, true), Ok("c".to_string()));
        assert_eq!(ok(issuer, issuer, false), Ok("c".to_string()));
        assert_eq!(ok(None, issuer, false), Ok("c".to_string()));
        assert_eq!(ok(None, None, true), Ok("c".to_string()));
        assert!(ok(Some("https://evil.example.com"), issuer, false)
            .unwrap_err()
            .contains("issuer mismatch"));
        assert!(ok(None, issuer, true)
            .unwrap_err()
            .contains("missing the 'iss'"));
    }

    #[test]
    fn test_evaluate_callback_issuer_mismatch_beats_error() {
        let (tx, _rx) = oneshot::channel::<CallbackResult>();
        let query = AuthCallback {
            state: Some("st".into()),
            error: Some("access_denied".into()),
            iss: Some("https://evil.example.com".into()),
            ..Default::default()
        };
        let state = callback_state(tx, Some("https://as.example.com"), false);
        assert!(evaluate_callback(&query, &state)
            .unwrap_err()
            .contains("issuer mismatch"));
    }

    #[test]
    fn test_evaluate_callback_requires_code() {
        let (tx, _rx) = oneshot::channel::<CallbackResult>();
        let query = AuthCallback {
            state: Some("st".into()),
            ..Default::default()
        };
        assert!(evaluate_callback(&query, &callback_state(tx, None, false)).is_err());
    }

    #[tokio::test]
    async fn test_reauthenticate_rejects_non_loopback_redirect() {
        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "http://localhost/auth".into(),
            token_url: "http://localhost/token".into(),
            par_url: "http://localhost/par".into(),
            redirect_url: "http://0.0.0.0:8082/callback".into(),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: Arc::new(String::new()),
            failure_html: Arc::new(String::new()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };
        let err = am.reauthenticate("user", None, None).await.unwrap_err();
        assert!(err.to_string().contains("RFC 8252"), "{err}");
    }

    #[tokio::test]
    async fn test_failed_flow_keeps_existing_credentials() {
        // A PAR failure must not replace the stored DPoP key.
        let vault = Vault::in_memory("svc");
        vault.store_token("user", "old-token").unwrap();
        vault.store_dpop_key("user", &[7u8; 32]).unwrap();
        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "http://localhost:1/auth".into(),
            token_url: "http://localhost:1/token".into(),
            par_url: "http://localhost:1/par".into(),
            redirect_url: "http://127.0.0.1:0/callback".into(),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: vault.clone(),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: Arc::new(String::new()),
            failure_html: Arc::new(String::new()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };
        assert!(am.reauthenticate("user", None, None).await.is_err());
        assert_eq!(vault.get_dpop_key("user").unwrap(), Some(vec![7u8; 32]));
        assert_eq!(vault.get_token("user").unwrap(), Some("old-token".into()));
    }

    #[tokio::test]
    async fn test_discover_rejects_insecure_endpoints() {
        let config = OidcConfig {
            client_id: "c".into(),
            redirect_url: "http://127.0.0.1:1/callback".into(),
            auth_url_override: Some("http://as.example.com/auth".into()),
            token_url_override: Some("https://as.example.com/token".into()),
            par_url_override: Some("https://as.example.com/par".into()),
            ..Default::default()
        };
        let err = AuthManager::discover(
            config.clone(),
            "https://mcp.example.com".into(),
            Vault::in_memory("svc"),
            None,
        )
        .await
        .err()
        .unwrap();
        assert!(err.to_string().contains("must use HTTPS"), "{err}");

        let allowed = OidcConfig {
            allow_insecure_http: true,
            ..config
        };
        // The insecure endpoint is accepted when explicitly allowed (the resource
        // name lookup fails quietly against the unreachable host).
        let am = AuthManager::discover(
            allowed,
            "http://127.0.0.1:1/rpc".into(),
            Vault::in_memory("svc"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(am.auth_url, "http://as.example.com/auth");
    }

    #[tokio::test]
    async fn test_auth_manager_set_internal_url_tx() {
        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "a".into(),
            token_url: "t".into(),
            par_url: "p".into(),
            redirect_url: "r".into(),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc_test_set_internal_url_tx"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };

        let (tx, _rx) = oneshot::channel::<String>();
        am.set_internal_url_tx(tx).await;

        let lock = am.internal_url_tx.lock().await;
        assert!(lock.is_some());
    }

    #[tokio::test]
    async fn test_auth_manager_get_token_fresh() -> Result<()> {
        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "a".into(),
            token_url: "t".into(),
            par_url: "p".into(),
            redirect_url: "r".into(),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc_test_get_token"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };
        am.vault.store_token("user", "token")?;

        assert_eq!(am.get_token("user")?, Some("token".into()));
        Ok(())
    }

    #[tokio::test]
    async fn test_auth_manager_discover_failure() {
        let config = OidcConfig {
            discovery_url: Some("http://localhost:1/invalid".into()),
            client_id: "c".into(),
            redirect_url: "r".into(),
            timeouts: crate::auth::Timeouts::fast(),
            ..Default::default()
        };
        let res =
            AuthManager::discover(config, "res".to_string(), Vault::in_memory("svc"), None).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_discover_prefers_configured_discovery_url() -> Result<()> {
        let app = Router::new().route(
            "/oidc",
            get(|| async {
                axum::Json(serde_json::json!({
                    "issuer": "https://configured.example.com",
                    "authorization_endpoint": "https://configured.example.com/auth",
                    "token_endpoint": "https://configured.example.com/token",
                    "pushed_authorization_request_endpoint": "https://configured.example.com/par"
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let config = OidcConfig {
            discovery_url: Some(format!("{base}/oidc")),
            client_id: "c".into(),
            redirect_url: "http://127.0.0.1:1/callback".into(),
            ..Default::default()
        };
        // The challenge's resource_metadata (a 404 here) must not override the
        // explicitly configured discovery URL.
        let am = AuthManager::discover(
            config,
            format!("{base}/rpc"),
            Vault::in_memory("svc"),
            Some(&format!("{base}/missing")),
        )
        .await?;
        assert_eq!(am.token_url, "https://configured.example.com/token");
        assert_eq!(am.par_url, "https://configured.example.com/par");
        Ok(())
    }

    #[tokio::test]
    async fn test_discover_overrides_skip_network() -> Result<()> {
        let config = OidcConfig {
            client_id: "c".into(),
            redirect_url: "http://127.0.0.1:1/callback".into(),
            auth_url_override: Some("https://as/auth".into()),
            token_url_override: Some("https://as/token".into()),
            par_url_override: Some("https://as/par".into()),
            ..Default::default()
        };
        let am = AuthManager::discover(
            config,
            "http://127.0.0.1:1/rpc".into(),
            Vault::in_memory("svc"),
            None,
        )
        .await?;
        assert_eq!(am.issuer_name, "Custom Provider");
        assert_eq!(am.resource_name, "http://127.0.0.1:1/rpc");
        Ok(())
    }

    #[tokio::test]
    async fn test_auth_manager_manual_token_exchange_failure() -> Result<()> {
        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "a".into(),
            token_url: "http://localhost:1/token".into(),
            par_url: "p".into(),
            redirect_url: "r".into(),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc_test_token_fail"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };
        let key = crate::crypto::DpopKey::generate();
        let res = am
            .manual_token_exchange("user", "code", "verifier", &key)
            .await;
        assert!(res.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_auth_manager_reauthenticate_addr_in_use() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "http://localhost/auth".into(),
            token_url: "http://localhost/token".into(),
            par_url: "http://localhost/par".into(),
            redirect_url: format!("http://127.0.0.1:{}/callback", addr.port()),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc_test_addr_in_use"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };

        // This should fail after 5 retries because the port is occupied by 'listener'
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            am.reauthenticate("user", None, None),
        )
        .await?;
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("Failed to bind"));
        Ok(())
    }

    #[tokio::test]
    async fn test_auth_manager_reauthenticate_timeout() -> Result<()> {
        let par_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let par_addr = par_listener.local_addr()?;
        let par_url = format!("http://127.0.0.1:{}/par", par_addr.port());

        let cb_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let cb_addr = cb_listener.local_addr()?;
        drop(cb_listener); // Release port so AuthManager can bind to it

        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "http://localhost/auth".into(),
            token_url: "http://localhost/token".into(),
            par_url: par_url.clone(),
            redirect_url: format!("http://127.0.0.1:{}/callback", cb_addr.port()),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc_test_reauth_timeout"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: std::sync::Arc::new(crate::templates::DEFAULT_SUCCESS_HTML.to_string()),
            failure_html: std::sync::Arc::new(crate::templates::DEFAULT_FAILURE_HTML.to_string()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
        };

        // Mock PAR response
        let par_app = Router::new().route(
            "/par",
            axum::routing::post(|| async move {
                axum::Json(serde_json::json!({
                    "request_uri": "urn:ietf:params:oauth:request_uri:123",
                    "expires_in": 3600
                }))
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(par_listener, par_app).await;
        });

        std::env::set_var("MCP_PASSPORT_SKIP_OPEN_BROWSER", "1");

        let res = am.reauthenticate("user", None, None).await;
        assert!(res.is_err());
        let err_msg = res.err().unwrap().to_string();
        assert!(err_msg.contains("Authentication timed out"));
        Ok(())
    }
}
