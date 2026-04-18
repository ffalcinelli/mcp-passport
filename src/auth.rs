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

#[derive(Clone)]
pub struct OidcConfig {
    pub discovery_url: Option<String>,
    pub client_id: String,
    pub redirect_url: String,
    pub auth_url_override: Option<String>,
    pub token_url_override: Option<String>,
    pub par_url_override: Option<String>,
    pub internal_url_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<String>>>>,
    pub internal_callback_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<SocketAddr>>>>,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("discovery_url", &self.discovery_url)
            .field("client_id", &self.client_id)
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

#[derive(Clone)]
pub struct AuthManager {
    client_id: String,
    auth_url: String,
    token_url: String,
    par_url: String,
    redirect_url: String,
    resource: String,
    http_client: HttpClient,
    vault: Vault,
    internal_url_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<String>>>>,
    internal_callback_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<SocketAddr>>>>,
}

#[derive(Deserialize, Debug)]
struct DiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    pushed_authorization_request_endpoint: Option<String>,
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
    pub async fn discover(
        oidc_config: OidcConfig,
        resource: String,
        service: &str,
        metadata_url_override: Option<&str>,
    ) -> Result<Self> {
        let http_client = HttpClient::new();

        let discovery_url = metadata_url_override
            .map(|s| s.to_string())
            .or_else(|| oidc_config.discovery_url.clone());

        let (auth_url, token_url, par_url) = if let Some(url) = discovery_url {
            info!("Fetching OIDC discovery from {}...", url);
            let resp = http_client.get(url.clone()).send().await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to fetch discovery document from {}: {}", url, resp.status());
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

            (auth, token, par)
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
            (auth, token, par)
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
            .with_state(AuthServerState { expected_state, tx });

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
                    warn!("Address {} already in use, retrying in 1s... (attempt {})", addr, i + 1);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        let listener = listener.unwrap();
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
        let code = match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
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

    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        self.vault.get_token(user_id)
    }
}

#[derive(Clone)]
struct AuthServerState {
    expected_state: String,
    tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<String>>>>,
}

async fn handle_callback(
    query: Query<AuthCallback>,
    State(state): State<AuthServerState>,
) -> impl IntoResponse {
    if query.state != state.expected_state {
        return (axum::http::StatusCode::BAD_REQUEST, "Invalid state").into_response();
    }
    let mut lock = state.tx.lock().await;
    if let Some(s) = lock.take() {
        let _ = s.send(query.code.clone());
        (
            axum::http::StatusCode::OK,
            "Authentication successful! You can close this tab and return to the terminal.",
        )
            .into_response()
    } else {
        (
            axum::http::StatusCode::GONE,
            "Already authenticated or timed out.",
        )
            .into_response()
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
    async fn test_handle_callback_invalid_state() {
        let (tx, _rx) = oneshot::channel::<String>();
        let state = AuthServerState {
            expected_state: "expected".to_string(),
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        };

        let query = Query(AuthCallback {
            code: "code".to_string(),
            state: "wrong".to_string(),
        });

        let response = handle_callback(query, State(state)).await.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
