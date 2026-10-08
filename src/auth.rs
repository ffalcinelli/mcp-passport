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
use crate::vault::{CredentialMeta, Vault};
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
    /// The issuer the (pre-registered) client belongs to. Discovery must find
    /// exactly this authorization server.
    pub expected_issuer: Option<String>,
    /// Ask for `offline_access` when the authorization server offers it.
    /// Off by default: providers list it even when the client may not use it
    /// (Keycloak then fails the code exchange with `not_allowed`).
    pub request_offline_access: bool,
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
            expected_issuer: None,
            request_offline_access: false,
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
            .field("expected_issuer", &self.expected_issuer)
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
    /// `scopes_supported` of the authorization server.
    as_scopes: Option<Vec<String>>,
    /// `scopes_supported` of the protected resource (RFC 9728).
    resource_scopes: Option<Vec<String>>,
    /// See [`OidcConfig::request_offline_access`].
    request_offline_access: bool,
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
    expires_in: Option<u64>,
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
        let (metadata, mut resource_name, resource_scopes) = if overrides_complete {
            (None, None, None)
        } else if let Some(url) = oidc_config.discovery_url.as_deref() {
            info!("Using configured OIDC discovery URL {}", url);
            net::require_secure_url(url, "OIDC discovery URL", oidc_config.allow_insecure_http)?;
            let metadata = discovery::fetch_configured_metadata(&http_client, url).await?;
            (Some(metadata), None, None)
        } else {
            info!("Discovering the authorization server for {}...", resource);
            let found = discovery::discover_from_resource(
                &http_client,
                &resource,
                resource_metadata_url,
                oidc_config.allow_insecure_http,
            )
            .await?;
            (
                Some(found.metadata),
                found.resource_name,
                found.resource_scopes,
            )
        };

        if let Some(m) = &metadata {
            if let Some(expected) = &oidc_config.expected_issuer {
                if &m.issuer != expected {
                    anyhow::bail!(
                        "The authorization server '{}' is not the one this client is registered \
                         with (--oidc-issuer '{}')",
                        m.issuer,
                        expected
                    );
                }
            }
            // MCP clients must confirm PKCE support before starting a flow.
            if !m.supports_pkce_s256() {
                anyhow::bail!(
                    "Authorization server '{}' does not advertise PKCE S256 in \
                     code_challenge_methods_supported; refusing to proceed",
                    m.issuer
                );
            }
            if is_url_client_id(&oidc_config.client_id) && !m.client_id_metadata_document_supported
            {
                warn!(
                    "Client ID '{}' is a metadata document URL, but '{}' does not advertise \
                     client_id_metadata_document_supported.",
                    oidc_config.client_id, m.issuer
                );
            }
        }
        if is_url_client_id(&oidc_config.client_id) {
            check_cimd_client_id(&oidc_config.client_id)?;
        }

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

        let issuer = metadata
            .as_ref()
            .map(|m| m.issuer.clone())
            .or_else(|| oidc_config.expected_issuer.clone());
        let as_scopes = metadata.as_ref().and_then(|m| m.scopes_supported.clone());
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
            as_scopes,
            resource_scopes,
            request_offline_access: oidc_config.request_offline_access,
        })
    }

    /// Delivers the next authorization URL to `tx` instead of opening a
    /// browser (for automation and tests).
    pub async fn set_internal_url_tx(&self, tx: oneshot::Sender<String>) {
        let mut lock = self.internal_url_tx.lock().await;
        *lock = Some(tx);
    }

    /// Reports the address the next loopback callback server binds to.
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
        let (server, rx) = self.setup_loopback_server(expected_state).await?;

        // 4. Pushed Authorization Request (PAR)
        let previous = self
            .bound_meta(user_id)?
            .map(|m| m.scopes)
            .unwrap_or_default();
        let scopes = self.select_scopes(scopes, &previous);
        let dpop_jkt = dpop_key.jkt()?;
        let par_data = match self
            .perform_par_request(&pkce_challenge, &state_val, &scopes, &dpop_jkt)
            .await
        {
            Ok(data) => data,
            Err(e) => {
                server.stop().await;
                return Err(e);
            }
        };

        // 5. Direct user to Auth URL
        if let Err(e) = self.open_auth_url(&par_data, url_tx).await {
            server.stop().await;
            return Err(e);
        }

        // 6. Wait for code from callback
        let callback = tokio::time::timeout(self.timeouts.auth, rx).await;
        server.stop().await;
        let code = match callback {
            Ok(Ok(Ok(code))) => code,
            Ok(Ok(Err(reason))) => anyhow::bail!("Authorization failed: {}", reason),
            _ => anyhow::bail!("Authentication timed out or failed to receive callback"),
        };

        // 7. Token Exchange with DPoP
        info!("Step 2: Exchanging code for DPoP-bound token...");
        self.manual_token_exchange(user_id, &code, &pkce_verifier, &dpop_key, &scopes)
            .await?;

        Ok(())
    }

    async fn setup_loopback_server(
        &self,
        expected_state: String,
    ) -> Result<(LoopbackServer, oneshot::Receiver<CallbackResult>)> {
        let redirect = net::require_loopback_redirect(&self.redirect_url)?;
        let (tx, rx) = oneshot::channel::<CallbackResult>();
        let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

        let app = Router::new()
            .route("/callback", get(handle_callback))
            // The browser must not keep a connection to this short-lived server:
            // a later login would otherwise reach the previous, stale handler.
            .layer(axum::middleware::map_response(
                |mut response: axum::response::Response| async move {
                    response.headers_mut().insert(
                        axum::http::header::CONNECTION,
                        axum::http::HeaderValue::from_static("close"),
                    );
                    response
                },
            ))
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

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let serve = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            if let Err(e) = serve.await {
                error!("Loopback server error: {:?}", e);
            }
        });

        Ok((
            LoopbackServer {
                handle,
                shutdown: Some(shutdown_tx),
            },
            rx,
        ))
    }

    async fn perform_par_request(
        &self,
        pkce_challenge: &str,
        state_val: &str,
        scopes: &[String],
        dpop_jkt: &str,
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
            // Binds the authorization code to our DPoP key (RFC 9449 §10).
            ("dpop_jkt", dpop_jkt),
        ];

        let scope_str = scopes.join(" ");
        if !scope_str.is_empty() {
            par_params.push(("scope", &scope_str));
        }

        let par_res = self
            .http_client
            .post(&self.par_url)
            .form(&par_params)
            .send()
            .await?;

        if !par_res.status().is_success() {
            let error_text = par_res.text().await?;
            error!("PAR request failed: {}", error_text);
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
        scopes: &[String],
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
        self.store_tokens(user_id, &tokens, Some(scopes))?;
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
        // Never send a refresh token to an authorization server that didn't issue it.
        if self.vault.get_meta(user_id)?.is_some() && self.bound_meta(user_id)?.is_none() {
            self.vault.delete_refresh_token(user_id)?;
            return Ok(false);
        }
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
                self.store_tokens(user_id, &tokens, None)?;
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

    /// Stores the tokens and what they were issued for. `scopes` is `None` for
    /// a refresh, which keeps the previously requested scopes.
    fn store_tokens(
        &self,
        user_id: &str,
        tokens: &TokenResponse,
        scopes: Option<&[String]>,
    ) -> Result<()> {
        self.vault.store_token(user_id, &tokens.access_token)?;
        // A refresh response without refresh_token keeps the current one (RFC 6749 §6).
        if let Some(refresh) = &tokens.refresh_token {
            self.vault.store_refresh_token(user_id, refresh)?;
        }
        let scopes = match scopes {
            Some(s) => s.to_vec(),
            None => self
                .vault
                .get_meta(user_id)?
                .map(|m| m.scopes)
                .unwrap_or_default(),
        };
        let expires_at = tokens.expires_in.map(|secs| unix_now() + secs);
        self.vault.store_meta(
            user_id,
            &CredentialMeta {
                issuer: self.issuer.clone(),
                scopes,
                expires_at,
            },
        )
    }

    /// The stored credential metadata, if the credentials come from this
    /// authorization server (or their issuer is unknown).
    fn bound_meta(&self, user_id: &str) -> Result<Option<CredentialMeta>> {
        Ok(self
            .vault
            .get_meta(user_id)?
            .filter(|meta| match (&meta.issuer, &self.issuer) {
                (Some(stored), Some(current)) => stored == current,
                _ => true,
            }))
    }

    /// Discards stored credentials issued by a different authorization server
    /// than the one discovered now. Credentials are bound to their issuer.
    pub fn enforce_issuer_binding(&self, user_id: &str) -> Result<()> {
        let Some(meta) = self.vault.get_meta(user_id)? else {
            return Ok(());
        };
        if self.bound_meta(user_id)?.is_none() {
            warn!(
                "Stored credentials were issued by '{}', but the server now uses '{}'; \
                 discarding them.",
                meta.issuer.as_deref().unwrap_or_default(),
                self.issuer.as_deref().unwrap_or_default()
            );
            self.vault.clear(user_id)?;
        }
        Ok(())
    }

    /// Scopes for a new authorization request (MCP scope selection strategy):
    /// the challenged scopes, else the resource's `scopes_supported`, plus the
    /// previously requested ones (step-up keeps earlier permissions). `openid`
    /// is added when the authorization server offers it, `offline_access` too
    /// when enabled.
    fn select_scopes(&self, challenged: Option<Vec<String>>, previous: &[String]) -> Vec<String> {
        let mut scopes: Vec<String> = previous.to_vec();
        let wanted = challenged
            .or_else(|| self.resource_scopes.clone())
            .unwrap_or_default();
        let offered = |s: &str| {
            self.as_scopes
                .as_ref()
                .is_some_and(|supported| supported.iter().any(|x| x == s))
        };
        let mut extra = Vec::new();
        // `openid` keeps working with providers that don't list their scopes.
        if self.as_scopes.is_none() || offered("openid") {
            extra.push("openid".to_string());
        }
        if self.request_offline_access && offered("offline_access") {
            extra.push("offline_access".to_string());
        }
        for s in wanted.into_iter().chain(extra) {
            if !scopes.contains(&s) {
                scopes.push(s);
            }
        }
        scopes
    }

    /// Retrieves the current access token for a user from the vault.
    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        self.vault.get_token(user_id)
    }
}

/// The loopback server receiving the authorization response.
struct LoopbackServer {
    handle: tokio::task::JoinHandle<()>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl LoopbackServer {
    /// Stops accepting, closes idle connections and frees the port.
    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if tokio::time::timeout(Duration::from_secs(2), &mut self.handle)
            .await
            .is_err()
        {
            self.handle.abort();
        }
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.handle.abort();
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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Whether the client id looks like a URL (a Client ID Metadata Document).
fn is_url_client_id(client_id: &str) -> bool {
    client_id.starts_with("https://") || client_id.starts_with("http://")
}

/// A Client ID Metadata Document URL must be https and have a path.
fn check_cimd_client_id(client_id: &str) -> Result<()> {
    let url = url::Url::parse(client_id)
        .with_context(|| format!("Invalid client ID metadata document URL '{client_id}'"))?;
    if url.scheme() != "https" || url.path().trim_matches('/').is_empty() {
        anyhow::bail!(
            "Client ID '{}' must be an https URL with a path to be used as a Client ID \
             Metadata Document",
            client_id
        );
    }
    Ok(())
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
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
    async fn test_loopback_servers_on_the_same_port_dont_share_connections() -> Result<()> {
        // A browser keeps connections alive; the second login's callback must
        // reach the second server, not the previous one.
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await?
            .local_addr()?
            .port();
        let am = AuthManager {
            client_id: "c".into(),
            auth_url: "http://localhost/auth".into(),
            token_url: "http://localhost/token".into(),
            par_url: "http://localhost/par".into(),
            redirect_url: format!("http://127.0.0.1:{port}/callback"),
            resource: "res".into(),
            http_client: reqwest::Client::new(),
            vault: Vault::in_memory("svc"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            success_html: Arc::new("OK".into()),
            failure_html: Arc::new("FAIL".into()),
            timeouts: Timeouts::fast(),
            issuer: None,
            iss_required: false,
            as_nonce: Arc::default(),
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
        };
        let browser = reqwest::Client::new(); // pools connections like a browser
        let callback = |state: &str| {
            format!("http://127.0.0.1:{port}/callback?state={state}&code=code-{state}")
        };

        for state in ["first", "second"] {
            let (server, rx) = am.setup_loopback_server(state.to_string()).await?;
            let resp = browser.get(callback(state)).send().await?;
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::OK,
                "callback for {state}"
            );
            assert_eq!(resp.headers()["connection"], "close");
            assert_eq!(rx.await?, Ok(format!("code-{state}")));
            server.stop().await;
        }
        Ok(())
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
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
                    "pushed_authorization_request_endpoint": "https://configured.example.com/par",
                    "code_challenge_methods_supported": ["S256"]
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

    /// Serves `doc` as a configured discovery document and runs `discover`.
    async fn discover_with(doc: serde_json::Value, config: OidcConfig) -> Result<AuthManager> {
        let app = Router::new().route(
            "/oidc",
            get(move || {
                let doc = doc.clone();
                async move { axum::Json(doc) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        AuthManager::discover(
            OidcConfig {
                discovery_url: Some(format!("{base}/oidc")),
                client_id: "c".into(),
                redirect_url: "http://127.0.0.1:1/callback".into(),
                ..config
            },
            format!("{base}/rpc"),
            Vault::in_memory("svc"),
            None,
        )
        .await
    }

    fn as_metadata(extra: serde_json::Value) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "issuer": "https://as.example.com",
            "authorization_endpoint": "https://as.example.com/auth",
            "token_endpoint": "https://as.example.com/token",
            "pushed_authorization_request_endpoint": "https://as.example.com/par",
            "code_challenge_methods_supported": ["S256"]
        });
        for (k, v) in extra.as_object().unwrap() {
            doc[k] = v.clone();
        }
        doc
    }

    #[tokio::test]
    async fn test_discover_requires_pkce_s256() {
        for methods in [serde_json::Value::Null, serde_json::json!(["plain"])] {
            let doc = as_metadata(serde_json::json!({"code_challenge_methods_supported": methods}));
            let err = discover_with(doc, OidcConfig::default())
                .await
                .err()
                .unwrap();
            assert!(err.to_string().contains("PKCE S256"), "{err}");
        }
    }

    #[tokio::test]
    async fn test_discover_checks_expected_issuer() -> Result<()> {
        let pinned = |issuer: &str| OidcConfig {
            expected_issuer: Some(issuer.into()),
            ..Default::default()
        };
        let err = discover_with(
            as_metadata(serde_json::json!({})),
            pinned("https://other.example.com"),
        )
        .await
        .err()
        .unwrap();
        assert!(err.to_string().contains("--oidc-issuer"), "{err}");
        let am = discover_with(
            as_metadata(serde_json::json!({})),
            pinned("https://as.example.com"),
        )
        .await?;
        assert_eq!(am.issuer.as_deref(), Some("https://as.example.com"));
        Ok(())
    }

    #[tokio::test]
    async fn test_discover_rejects_invalid_cimd_client_id() {
        let res = AuthManager::discover(
            OidcConfig {
                client_id: "http://client.example.com/meta.json".into(),
                redirect_url: "http://127.0.0.1:1/callback".into(),
                auth_url_override: Some("https://as/auth".into()),
                token_url_override: Some("https://as/token".into()),
                par_url_override: Some("https://as/par".into()),
                ..Default::default()
            },
            "http://127.0.0.1:1/rpc".into(),
            Vault::in_memory("svc"),
            None,
        )
        .await;
        assert!(res
            .err()
            .unwrap()
            .to_string()
            .contains("https URL with a path"));
        assert!(check_cimd_client_id("https://client.example.com/oauth/meta.json").is_ok());
        assert!(check_cimd_client_id("https://client.example.com/").is_err());
    }

    #[tokio::test]
    async fn test_select_scopes() -> Result<()> {
        let mut am = discover_with(
            as_metadata(
                serde_json::json!({"scopes_supported": ["openid", "offline_access", "mcp:read"]}),
            ),
            OidcConfig {
                request_offline_access: true,
                ..Default::default()
            },
        )
        .await?;
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        // Challenge scopes win; openid and offline_access are offered by the AS.
        assert_eq!(
            am.select_scopes(Some(v(&["files:read"])), &[]),
            v(&["files:read", "openid", "offline_access"])
        );
        // Step-up keeps what was requested before.
        assert_eq!(
            am.select_scopes(Some(v(&["files:write"])), &v(&["files:read", "openid"])),
            v(&["files:read", "openid", "files:write", "offline_access"])
        );
        // Without a challenge: the resource's scopes_supported.
        am.resource_scopes = Some(v(&["mcp:read"]));
        assert_eq!(
            am.select_scopes(None, &[]),
            v(&["mcp:read", "openid", "offline_access"])
        );
        // An AS that lists scopes without openid doesn't get it.
        am.as_scopes = Some(v(&["mcp:read"]));
        assert_eq!(am.select_scopes(None, &[]), v(&["mcp:read"]));
        // offline_access is only requested when enabled.
        am.as_scopes = Some(v(&["openid", "offline_access"]));
        am.request_offline_access = false;
        assert_eq!(am.select_scopes(None, &[]), v(&["mcp:read", "openid"]));
        // An AS that lists no scopes keeps the historical openid.
        am.as_scopes = None;
        am.resource_scopes = None;
        assert_eq!(am.select_scopes(None, &[]), v(&["openid"]));
        Ok(())
    }

    #[tokio::test]
    async fn test_issuer_binding() -> Result<()> {
        let am = discover_with(as_metadata(serde_json::json!({})), OidcConfig::default()).await?;
        let other = CredentialMeta {
            issuer: Some("https://previous-as.example.com".into()),
            ..Default::default()
        };

        // Credentials from another AS are discarded.
        am.vault.store_token("u", "t")?;
        am.vault.store_refresh_token("u", "r")?;
        am.vault.store_meta("u", &other)?;
        am.enforce_issuer_binding("u")?;
        assert_eq!(am.vault.get_token("u")?, None);
        assert_eq!(am.vault.get_refresh_token("u")?, None);

        // ...and their refresh token is never sent anywhere.
        am.vault.store_refresh_token("u", "r")?;
        am.vault.store_meta("u", &other)?;
        assert!(!am.refresh("u").await?);
        assert_eq!(am.vault.get_refresh_token("u")?, None);

        // Credentials from this AS, or without metadata, are kept.
        am.vault.store_token("u", "t")?;
        am.vault.store_meta(
            "u",
            &CredentialMeta {
                issuer: Some("https://as.example.com".into()),
                ..Default::default()
            },
        )?;
        am.enforce_issuer_binding("u")?;
        assert_eq!(am.vault.get_token("u")?, Some("t".into()));
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
        };
        let key = crate::crypto::DpopKey::generate();
        let res = am
            .manual_token_exchange("user", "code", "verifier", &key, &[])
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
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
            as_scopes: None,
            resource_scopes: None,
            request_offline_access: false,
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
