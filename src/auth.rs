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
use crate::vault::Vault;
use crate::Result;
use anyhow::Context;
use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, TokenUrl,
};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
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
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("discovery_url", &self.discovery_url)
            .field("client_id", &self.client_id)
            .field("redirect_url", &self.redirect_url)
            .field("template_dir", &self.template_dir)
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
    /// Directory containing custom templates for success/failure pages.
    template_dir: Option<std::path::PathBuf>,
    /// Human-friendly name of the identity provider.
    issuer_name: String,
    /// Human-friendly name of the protected resource.
    resource_name: String,
}

#[derive(Deserialize, Debug)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    pushed_authorization_request_endpoint: Option<String>,
    #[serde(rename = "organization_name")]
    organization_name: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ResourceMetadata {
    resource_name: Option<String>,
}

#[derive(Deserialize)]
struct AuthCallback {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct ParResponse {
    request_uri: String,
    #[allow(dead_code)]
    expires_in: u64,
}

impl AuthManager {
    /// Discovers OIDC endpoints via the discovery document or overrides.
    pub async fn discover(
        oidc_config: OidcConfig,
        resource: String,
        service: &str,
        metadata_url_override: Option<&str>,
    ) -> Result<Self> {
        let http_client = HttpClient::new();

        let discovery_url = metadata_url_override.or(oidc_config.discovery_url.as_deref());

        let (auth_url, token_url, par_url, issuer_name) = if let Some(url) = discovery_url {
            info!("Fetching OIDC discovery from {}...", url);
            let resp = http_client.get(url).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!(
                    "Failed to fetch discovery document from {}: {}",
                    url,
                    resp.status()
                );
            }
            let doc: DiscoveryDocument = resp.json().await?;

            let auth = oidc_config
                .auth_url_override
                .clone()
                .unwrap_or(doc.authorization_endpoint);
            let token = oidc_config
                .token_url_override
                .clone()
                .unwrap_or(doc.token_endpoint);
            let par = oidc_config.par_url_override.clone().or(doc.pushed_authorization_request_endpoint)
                .context("Discovery document missing pushed_authorization_request_endpoint and no override provided")?;

            let name = doc.organization_name.unwrap_or(doc.issuer);
            (auth, token, par, name)
        } else {
            let auth = oidc_config
                .auth_url_override
                .clone()
                .context("auth_url is required when discovery_url is missing")?;
            let token = oidc_config
                .token_url_override
                .clone()
                .context("token_url is required when discovery_url is missing")?;
            let par = oidc_config
                .par_url_override
                .clone()
                .context("par_url is required when discovery_url is missing")?;
            (auth, token, par, "Custom Provider".to_string())
        };

        // Fetch Protected Resource Metadata (RFC 9728)
        let resource_name = if let Ok(mut res_url) = url::Url::parse(&resource) {
            res_url.set_path("/.well-known/oauth-protected-resource");
            res_url.set_query(None);
            res_url.set_fragment(None);

            info!("Fetching Protected Resource Metadata from {}...", res_url);
            match http_client.get(res_url.as_str()).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<ResourceMetadata>().await {
                        Ok(meta) => meta.resource_name.unwrap_or_else(|| resource.clone()),
                        Err(_) => resource.clone(),
                    }
                }
                _ => resource.clone(),
            }
        } else {
            resource.clone()
        };

        Ok(Self {
            client_id: oidc_config.client_id,
            auth_url,
            token_url,
            par_url,
            redirect_url: oidc_config.redirect_url,
            resource,
            http_client,
            vault: Vault::new(service),
            internal_url_tx: oidc_config.internal_url_tx,
            internal_callback_tx: oidc_config.internal_callback_tx,
            template_dir: oidc_config.template_dir,
            issuer_name,
            resource_name,
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

        // 1. Generate and store new ephemeral DPoP key
        let dpop_key = DpopKey::generate();
        self.vault.store_dpop_key(user_id, &dpop_key.to_bytes())?;

        // 2. Prepare PKCE and State
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let csrf_token = CsrfToken::new_random();
        let state_val = csrf_token.secret().clone();

        // 3. Setup Loopback Server to catch the callback
        let (tx, rx) = oneshot::channel::<String>();
        let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
        let expected_state = state_val.clone();

        let app = Router::new()
            .route("/callback", get(handle_callback))
            .with_state(AuthServerState {
                expected_state,
                tx,
                template_dir: self.template_dir.clone(),
                issuer_name: self.issuer_name.clone(),
                resource_name: self.resource_name.clone(),
            });

        let addr: SocketAddr = self
            .redirect_url
            .parse::<url::Url>()?
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
                    let wait = if cfg!(test) {
                        std::time::Duration::from_millis(10)
                    } else {
                        std::time::Duration::from_secs(1)
                    };
                    tokio::time::sleep(wait).await;
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

        // 4. Pushed Authorization Request (PAR)
        info!("Step 1: Pushed Authorization Request (PAR)...");
        let mut par_params = vec![
            ("client_id", self.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", self.redirect_url.as_str()),
            ("code_challenge", pkce_challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", &state_val),
            ("resource", self.resource.as_str()),
        ];

        let mut s_vec = if let Some(ref s) = scopes {
            s.clone()
        } else {
            vec![]
        };
        if !s_vec.contains(&"openid".to_string()) {
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

        // 5. Direct user to Auth URL
        let auth_url = format!(
            "{}?client_id={}&response_type=code&request_uri={}",
            self.auth_url, self.client_id, par_data.request_uri
        );

        warn!("****************************************************************");
        warn!("ACTION REQUIRED: Please visit the following URL to authenticate:");
        warn!("{}", auth_url);
        warn!("****************************************************************");

        // Attempt to open the browser automatically (skip if in tests or explicitly requested)
        let skip_open = std::env::var("MCP_PASSPORT_SKIP_OPEN_BROWSER").is_ok();
        let mut has_listener = url_tx.is_some();

        if !has_listener {
            let lock = self.internal_url_tx.lock().await;
            has_listener = lock.is_some();
        }

        if !skip_open && !has_listener {
            if let Err(e) = open::that(&auth_url) {
                warn!(
                    "Failed to open browser automatically: {}. Please copy the URL above.",
                    e
                );
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

        // 6. Wait for code from callback
        let timeout_duration = if cfg!(test) {
            std::time::Duration::from_millis(500)
        } else {
            std::time::Duration::from_secs(300)
        };
        let code = match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(c)) => c,
            _ => {
                server_handle.abort();
                anyhow::bail!("Authentication timed out or failed to receive callback");
            }
        };
        server_handle.abort();

        // 7. Token Exchange with DPoP
        info!("Step 2: Exchanging code for DPoP-bound token...");
        let _oauth_client = BasicClient::new(ClientId::new(self.client_id.clone()))
            .set_auth_uri(AuthUrl::new(self.auth_url.clone())?)
            .set_token_uri(TokenUrl::new(self.token_url.clone())?)
            .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone())?);

        // We use manual token exchange because FAPI 2.0 requires DPoP in headers,
        // which the oauth2 crate doesn't natively support yet for the exchange_code call.
        self.manual_token_exchange(
            user_id,
            &AuthorizationCode::new(code),
            &pkce_verifier,
            &dpop_key,
        )
        .await?;

        Ok(())
    }

    async fn manual_token_exchange(
        &self,
        user_id: &str,
        code: &AuthorizationCode,
        pkce_verifier: &PkceCodeVerifier,
        dpop_key: &DpopKey,
    ) -> Result<()> {
        let dpop_proof = dpop_key.generate_proof("POST", &self.token_url)?;

        let params = vec![
            ("grant_type", "authorization_code"),
            ("client_id", self.client_id.as_str()),
            ("code", code.secret().as_str()),
            ("redirect_uri", self.redirect_url.as_str()),
            ("code_verifier", pkce_verifier.secret().as_str()),
            ("resource", self.resource.as_str()),
        ];

        let res = self
            .http_client
            .post(&self.token_url)
            .header("DPoP", dpop_proof)
            .form(&params)
            .send()
            .await?;

        if !res.status().is_success() {
            let err = res.text().await?;
            error!("Token exchange failed: {}", err);
            anyhow::bail!("Token exchange failed: {}", err);
        }

        #[derive(Deserialize)]
        struct TokenSuccess {
            access_token: String,
        }

        let data: TokenSuccess = res.json().await?;
        self.vault.store_token(user_id, &data.access_token)?;
        info!("Successfully acquired and stored DPoP-bound token.");

        Ok(())
    }

    /// Retrieves the current access token for a user from the vault.
    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        self.vault.get_token(user_id)
    }
}

#[derive(Clone)]
struct AuthServerState {
    expected_state: String,
    tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<String>>>>,
    template_dir: Option<std::path::PathBuf>,
    issuer_name: String,
    resource_name: String,
}

async fn handle_callback(
    query: Query<AuthCallback>,
    State(state): State<AuthServerState>,
) -> impl IntoResponse {
    if query.state != state.expected_state {
        let mut html = if let Some(dir) = &state.template_dir {
            tokio::fs::read_to_string(dir.join("failure.html"))
                .await
                .unwrap_or_else(|_| crate::templates::DEFAULT_FAILURE_HTML.to_string())
        } else {
            crate::templates::DEFAULT_FAILURE_HTML.to_string()
        };
        html = html.replace("{{ERROR_MESSAGE}}", "Invalid state");
        html = html.replace("{{ISSUER_NAME}}", &state.issuer_name);
        html = html.replace("{{RESOURCE_NAME}}", &state.resource_name);
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Html(html),
        )
            .into_response();
    }
    let mut lock = state.tx.lock().await;
    if let Some(s) = lock.take() {
        let _ = s.send(query.code.clone());
        let mut html = if let Some(dir) = &state.template_dir {
            tokio::fs::read_to_string(dir.join("success.html"))
                .await
                .unwrap_or_else(|_| crate::templates::DEFAULT_SUCCESS_HTML.to_string())
        } else {
            crate::templates::DEFAULT_SUCCESS_HTML.to_string()
        };
        html = html.replace("{{ISSUER_NAME}}", &state.issuer_name);
        html = html.replace("{{RESOURCE_NAME}}", &state.resource_name);
        (axum::http::StatusCode::OK, axum::response::Html(html)).into_response()
    } else {
        let mut html = if let Some(dir) = &state.template_dir {
            tokio::fs::read_to_string(dir.join("failure.html"))
                .await
                .unwrap_or_else(|_| crate::templates::DEFAULT_FAILURE_HTML.to_string())
        } else {
            crate::templates::DEFAULT_FAILURE_HTML.to_string()
        };
        html = html.replace("{{ERROR_MESSAGE}}", "Already authenticated or timed out.");
        html = html.replace("{{ISSUER_NAME}}", &state.issuer_name);
        html = html.replace("{{RESOURCE_NAME}}", &state.resource_name);
        (axum::http::StatusCode::GONE, axum::response::Html(html)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handle_callback_success() {
        let (tx, mut rx) = oneshot::channel::<String>();
        let state = AuthServerState {
            expected_state: "test_state".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            template_dir: None,
            issuer_name: "Test Issuer".to_string(),
            resource_name: "Test Resource".to_string(),
        };

        let query = Query(AuthCallback {
            code: "test_code".to_string(),
            state: "test_state".to_string(),
        });

        let response = handle_callback(query, State(state)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(rx.try_recv().unwrap(), "test_code");
    }

    #[tokio::test]
    async fn test_handle_callback_with_templates() -> Result<()> {
        let temp_dir = std::env::temp_dir().join(format!("mcp_test_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await?;
        tokio::fs::write(temp_dir.join("success.html"), "SUCCESS {{RESOURCE_NAME}}").await?;
        tokio::fs::write(temp_dir.join("failure.html"), "FAILURE {{ERROR_MESSAGE}}").await?;

        let (tx, mut rx) = oneshot::channel::<String>();
        let state = AuthServerState {
            expected_state: "test_state".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            template_dir: Some(temp_dir.clone()),
            issuer_name: "Test Issuer".to_string(),
            resource_name: "Test Resource".to_string(),
        };

        // 1. Success case
        let query_ok = Query(AuthCallback {
            code: "test_code".to_string(),
            state: "test_state".to_string(),
        });
        let res_ok = handle_callback(query_ok, State(state.clone()))
            .await
            .into_response();
        assert_eq!(res_ok.status(), axum::http::StatusCode::OK);
        let body_ok = axum::body::to_bytes(res_ok.into_body(), 1024)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body_ok).contains("SUCCESS Test Resource"));
        assert_eq!(rx.try_recv().unwrap(), "test_code");

        // 2. Invalid state case
        let query_err = Query(AuthCallback {
            code: "c".to_string(),
            state: "wrong".to_string(),
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
            code: "c".to_string(),
            state: "test_state".to_string(),
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
        let (tx, _rx) = oneshot::channel::<String>();
        let state = AuthServerState {
            expected_state: "expected".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
            template_dir: None,
            issuer_name: "Test Issuer".to_string(),
            resource_name: "Test Resource".to_string(),
        };

        let query = Query(AuthCallback {
            code: "code".to_string(),
            state: "wrong".to_string(),
        });

        let response = handle_callback(query, State(state)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
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
            vault: Vault::new("svc_test_set_internal_url_tx"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            template_dir: None,
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
            vault: Vault::new("svc_test_get_token"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            template_dir: None,
        };
        std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
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
            auth_url_override: None,
            token_url_override: None,
            par_url_override: None,
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            template_dir: None,
        };
        let res = AuthManager::discover(config, "res".to_string(), "svc", None).await;
        assert!(res.is_err());
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
            vault: Vault::new("svc_test_token_fail"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            template_dir: None,
        };
        let key = crate::crypto::DpopKey::generate();
        let code = AuthorizationCode::new("code".to_string());
        let verifier = PkceCodeVerifier::new("verifier".to_string());
        let res = am
            .manual_token_exchange("user", &code, &verifier, &key)
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
            vault: Vault::new("svc_test_addr_in_use"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            template_dir: None,
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
            vault: Vault::new("svc_test_reauth_timeout"),
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
            issuer_name: "Mock Issuer".into(),
            resource_name: "Mock Resource".into(),
            template_dir: None,
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
