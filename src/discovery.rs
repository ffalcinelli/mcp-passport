//! # Authorization Server Discovery
//!
//! Locates the authorization server (AS) protecting an MCP server, following the
//! MCP Authorization specification (2025-11-25):
//!
//! 1. **RFC 9728 Protected Resource Metadata**: fetched from the
//!    `resource_metadata` URL in a `WWW-Authenticate` challenge, or from the
//!    well-known URI derived from the resource (path-inserted first, then root).
//! 2. **RFC 8414 / OpenID Connect Discovery**: the AS metadata of the first entry
//!    in `authorization_servers`, whose `issuer` must match that entry.
//!
//! For backwards compatibility, a resource metadata document that directly
//! contains AS metadata (`authorization_endpoint`, ...) is accepted with a warning.

use crate::Result;
use anyhow::{bail, Context};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, info, warn};
use url::Url;

const RESOURCE_METADATA_SUFFIX: &str = "oauth-protected-resource";
const OAUTH_AS_SUFFIX: &str = "oauth-authorization-server";
const OIDC_SUFFIX: &str = "openid-configuration";

/// The subset of RFC 8414 / OIDC Discovery metadata used by mcp-passport.
#[derive(Deserialize, Debug, Clone)]
pub(crate) struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub pushed_authorization_request_endpoint: Option<String>,
    pub organization_name: Option<String>,
    /// RFC 9207: the AS returns `iss` in the authorization response.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

/// The subset of RFC 9728 Protected Resource Metadata used by mcp-passport.
#[derive(Deserialize, Debug, Default)]
struct ResourceMetadata {
    resource: Option<String>,
    #[serde(default)]
    authorization_servers: Vec<String>,
    resource_name: Option<String>,
}

/// What dynamic discovery produced.
#[derive(Debug)]
pub(crate) struct Discovered {
    pub metadata: AuthServerMetadata,
    /// `resource_name` from the protected resource metadata, if any.
    pub resource_name: Option<String>,
}

/// Builds a well-known URI by inserting `/.well-known/<suffix>` between the host
/// and the path of `id`, dropping any trailing `/` (RFC 8414 §3.1, RFC 9728 §3.1).
fn well_known_url(id: &Url, suffix: &str) -> Url {
    let mut u = id.clone();
    let path = id.path().trim_end_matches('/');
    u.set_path(&format!("/.well-known/{suffix}{path}"));
    u.set_query(None);
    u.set_fragment(None);
    u
}

/// Candidate RFC 9728 metadata URLs for a resource: path-inserted, then root.
pub(crate) fn resource_metadata_candidates(resource: &str) -> Result<Vec<Url>> {
    let r = Url::parse(resource).context("Failed to parse resource URL")?;
    let inserted = well_known_url(&r, RESOURCE_METADATA_SUFFIX);
    let mut root = r;
    root.set_path("");
    let root = well_known_url(&root, RESOURCE_METADATA_SUFFIX);

    let mut candidates = vec![inserted];
    if root != candidates[0] {
        candidates.push(root);
    }
    Ok(candidates)
}

/// Candidate AS metadata URLs for an issuer, in the order the MCP spec lists them.
fn auth_server_metadata_candidates(issuer: &Url) -> Vec<Url> {
    let mut candidates = vec![
        well_known_url(issuer, OAUTH_AS_SUFFIX),
        well_known_url(issuer, OIDC_SUFFIX),
    ];
    let path = issuer.path().trim_end_matches('/');
    if !path.is_empty() {
        let mut appended = issuer.clone();
        appended.set_path(&format!("{path}/.well-known/{OIDC_SUFFIX}"));
        appended.set_query(None);
        appended.set_fragment(None);
        candidates.push(appended);
    }
    candidates
}

async fn fetch_json(client: &Client, url: &Url) -> Result<Value> {
    info!("Fetching metadata from {}...", url);
    let resp = client
        .get(url.as_str())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("Failed to fetch {url}"))?;
    if !resp.status().is_success() {
        bail!("Failed to fetch {}: {}", url, resp.status());
    }
    resp.json()
        .await
        .with_context(|| format!("Invalid JSON returned by {url}"))
}

/// Returns the first candidate that yields a JSON document.
async fn fetch_first(client: &Client, candidates: &[Url]) -> Result<(Url, Value)> {
    let mut errors = Vec::with_capacity(candidates.len());
    for url in candidates {
        match fetch_json(client, url).await {
            Ok(doc) => return Ok((url.clone(), doc)),
            Err(e) => {
                debug!("{:#}", e);
                errors.push(format!("{e:#}"));
            }
        }
    }
    bail!("no metadata document found ({})", errors.join("; "))
}

/// Compares two identifiers, ignoring a single trailing `/`.
fn same_identifier(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// The `resource` in the metadata must identify the server we are talking to:
/// same origin, and a path that is a prefix of the MCP endpoint path.
fn validate_resource_field(declared: Option<&str>, resource: &str) -> Result<()> {
    let Some(declared) = declared else {
        warn!("Protected resource metadata has no 'resource' field (required by RFC 9728).");
        return Ok(());
    };
    let d = Url::parse(declared).with_context(|| format!("Invalid 'resource' {declared}"))?;
    let r = Url::parse(resource).context("Failed to parse resource URL")?;
    let d_path = d.path().trim_end_matches('/');
    let r_path = r.path().trim_end_matches('/');
    let path_ok = r_path == d_path || r_path.starts_with(&format!("{d_path}/"));
    if d.origin() != r.origin() || !path_ok {
        bail!(
            "Protected resource metadata is for '{}', not for '{}' (RFC 9728 §3.3)",
            declared,
            resource
        );
    }
    Ok(())
}

/// Fetches and validates the metadata of the authorization server `issuer`.
async fn fetch_auth_server_metadata(client: &Client, issuer: &str) -> Result<AuthServerMetadata> {
    let issuer_url =
        Url::parse(issuer).with_context(|| format!("Invalid authorization server '{issuer}'"))?;
    let (url, doc) = fetch_first(client, &auth_server_metadata_candidates(&issuer_url))
        .await
        .with_context(|| format!("Failed to fetch metadata for authorization server {issuer}"))?;
    let metadata: AuthServerMetadata = serde_json::from_value(doc)
        .with_context(|| format!("Invalid authorization server metadata at {url}"))?;
    if !same_identifier(&metadata.issuer, issuer) {
        bail!(
            "Issuer mismatch: {} declares issuer '{}' but '{}' was expected (RFC 8414 §3.3)",
            url,
            metadata.issuer,
            issuer
        );
    }
    Ok(metadata)
}

/// Fetches an explicitly configured discovery document (no issuer check: the URL
/// comes from the user's configuration).
pub(crate) async fn fetch_configured_metadata(
    client: &Client,
    url: &str,
) -> Result<AuthServerMetadata> {
    let url = Url::parse(url).with_context(|| format!("Invalid discovery URL '{url}'"))?;
    let doc = fetch_json(client, &url).await?;
    serde_json::from_value(doc).with_context(|| format!("Invalid discovery document at {url}"))
}

/// Discovers the authorization server for `resource`, starting from the
/// `resource_metadata` URL of a challenge when available.
pub(crate) async fn discover_from_resource(
    client: &Client,
    resource: &str,
    resource_metadata_url: Option<&str>,
    allow_insecure_http: bool,
) -> Result<Discovered> {
    let candidates = match resource_metadata_url {
        Some(u) => vec![Url::parse(u).with_context(|| format!("Invalid resource_metadata '{u}'"))?],
        None => resource_metadata_candidates(resource)?,
    };
    let (url, doc) = fetch_first(client, &candidates)
        .await
        .context("Failed to fetch protected resource metadata")?;

    let rm: ResourceMetadata = serde_json::from_value(doc.clone())
        .with_context(|| format!("Invalid protected resource metadata at {url}"))?;

    if let Some(issuer) = rm.authorization_servers.first() {
        validate_resource_field(rm.resource.as_deref(), resource)?;
        if rm.authorization_servers.len() > 1 {
            info!(
                "Resource lists {} authorization servers; using '{}'.",
                rm.authorization_servers.len(),
                issuer
            );
        }
        crate::net::require_secure_url(issuer, "authorization server", allow_insecure_http)?;
        let metadata = fetch_auth_server_metadata(client, issuer).await?;
        return Ok(Discovered {
            metadata,
            resource_name: rm.resource_name,
        });
    }

    if doc.get("authorization_endpoint").is_some() {
        warn!(
            "{} returned authorization server metadata instead of RFC 9728 protected resource \
             metadata; using it directly (legacy mode).",
            url
        );
        let metadata: AuthServerMetadata = serde_json::from_value(doc)
            .with_context(|| format!("Invalid authorization server metadata at {url}"))?;
        return Ok(Discovered {
            metadata,
            resource_name: rm.resource_name,
        });
    }

    bail!("Protected resource metadata at {url} lists no authorization_servers")
}

/// Best-effort lookup of the human-friendly `resource_name` (RFC 9728).
pub(crate) async fn fetch_resource_name(client: &Client, resource: &str) -> Option<String> {
    let candidates = resource_metadata_candidates(resource).ok()?;
    for url in candidates {
        if let Ok(doc) = fetch_json(client, &url).await {
            if let Some(name) = doc.get("resource_name").and_then(Value::as_str) {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Json, Router};
    use serde_json::json;

    fn urls(v: Vec<Url>) -> Vec<String> {
        v.into_iter().map(|u| u.to_string()).collect()
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{}", addr)
    }

    fn as_doc(issuer: &str) -> Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        })
    }

    #[test]
    fn test_resource_metadata_candidates() {
        assert_eq!(
            urls(resource_metadata_candidates("http://example.com/api").unwrap()),
            vec![
                "http://example.com/.well-known/oauth-protected-resource/api",
                "http://example.com/.well-known/oauth-protected-resource",
            ]
        );
        // Trailing slash is dropped, query is removed.
        assert_eq!(
            urls(resource_metadata_candidates("http://example.com/api/?x=1").unwrap()),
            vec![
                "http://example.com/.well-known/oauth-protected-resource/api",
                "http://example.com/.well-known/oauth-protected-resource",
            ]
        );
        // Root resource has a single candidate.
        assert_eq!(
            urls(resource_metadata_candidates("http://localhost:8081").unwrap()),
            vec!["http://localhost:8081/.well-known/oauth-protected-resource"]
        );
        assert!(resource_metadata_candidates("not a url").is_err());
    }

    #[test]
    fn test_auth_server_metadata_candidates() {
        let with_path = Url::parse("https://auth.example.com/realms/mcp").unwrap();
        assert_eq!(
            urls(auth_server_metadata_candidates(&with_path)),
            vec![
                "https://auth.example.com/.well-known/oauth-authorization-server/realms/mcp",
                "https://auth.example.com/.well-known/openid-configuration/realms/mcp",
                "https://auth.example.com/realms/mcp/.well-known/openid-configuration",
            ]
        );
        let root = Url::parse("https://auth.example.com").unwrap();
        assert_eq!(
            urls(auth_server_metadata_candidates(&root)),
            vec![
                "https://auth.example.com/.well-known/oauth-authorization-server",
                "https://auth.example.com/.well-known/openid-configuration",
            ]
        );
    }

    #[test]
    fn test_validate_resource_field() {
        let remote = "https://mcp.example.com/mcp";
        assert!(validate_resource_field(Some("https://mcp.example.com/mcp"), remote).is_ok());
        assert!(validate_resource_field(Some("https://mcp.example.com/mcp/"), remote).is_ok());
        assert!(validate_resource_field(Some("https://mcp.example.com"), remote).is_ok());
        assert!(validate_resource_field(None, remote).is_ok());
        assert!(validate_resource_field(Some("https://evil.example.com/mcp"), remote).is_err());
        assert!(validate_resource_field(Some("http://mcp.example.com/mcp"), remote).is_err());
        assert!(validate_resource_field(Some("https://mcp.example.com/other"), remote).is_err());
        assert!(validate_resource_field(Some("https://mcp.example.com/mc"), remote).is_err());
    }

    #[tokio::test]
    async fn test_two_step_discovery_with_path_inserted_well_known() {
        // The AS lives under /realms/mcp and only serves the OIDC appended form.
        let app = Router::new()
            .route(
                "/.well-known/oauth-protected-resource/rpc",
                get(|headers: axum::http::HeaderMap| async move {
                    let host = headers["host"].to_str().unwrap().to_string();
                    Json(json!({
                        "resource": format!("http://{host}/rpc"),
                        "authorization_servers": [format!("http://{host}/realms/mcp")],
                        "resource_name": "Spec Resource"
                    }))
                }),
            )
            .route(
                "/realms/mcp/.well-known/openid-configuration",
                get(|headers: axum::http::HeaderMap| async move {
                    let host = headers["host"].to_str().unwrap().to_string();
                    Json(as_doc(&format!("http://{host}/realms/mcp")))
                }),
            );
        let base = serve(app).await;
        let client = Client::new();

        let found = discover_from_resource(&client, &format!("{base}/rpc"), None, false)
            .await
            .unwrap();
        assert_eq!(found.metadata.issuer, format!("{base}/realms/mcp"));
        assert_eq!(
            found.metadata.token_endpoint,
            format!("{base}/realms/mcp/token")
        );
        assert_eq!(found.resource_name.as_deref(), Some("Spec Resource"));
    }

    #[tokio::test]
    async fn test_discovery_from_challenge_url_and_rfc8414_well_known() {
        let app = Router::new()
            .route(
                "/meta",
                get(|headers: axum::http::HeaderMap| async move {
                    let host = headers["host"].to_str().unwrap().to_string();
                    Json(json!({
                        "resource": format!("http://{host}"),
                        "authorization_servers": [format!("http://{host}")]
                    }))
                }),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(|headers: axum::http::HeaderMap| async move {
                    let host = headers["host"].to_str().unwrap().to_string();
                    Json(as_doc(&format!("http://{host}")))
                }),
            );
        let base = serve(app).await;
        let found = discover_from_resource(
            &Client::new(),
            &format!("{base}/rpc"),
            Some(&format!("{base}/meta")),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            found.metadata.authorization_endpoint,
            format!("{base}/auth")
        );
        assert_eq!(found.resource_name, None);
    }

    #[tokio::test]
    async fn test_discovery_rejects_issuer_mismatch() {
        let app = Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(|headers: axum::http::HeaderMap| async move {
                    let host = headers["host"].to_str().unwrap().to_string();
                    Json(json!({ "authorization_servers": [format!("http://{host}")] }))
                }),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(|| async { Json(as_doc("https://attacker.example.com")) }),
            );
        let base = serve(app).await;
        let err = discover_from_resource(&Client::new(), &base, None, false)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("Issuer mismatch"), "{err:#}");
    }

    #[tokio::test]
    async fn test_discovery_rejects_foreign_resource() {
        let app = Router::new().route(
            "/.well-known/oauth-protected-resource",
            get(|| async {
                Json(json!({
                    "resource": "https://other.example.com",
                    "authorization_servers": ["https://auth.example.com"]
                }))
            }),
        );
        let base = serve(app).await;
        let err = discover_from_resource(&Client::new(), &base, None, false)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("RFC 9728"), "{err:#}");
    }

    #[tokio::test]
    async fn test_discovery_legacy_as_metadata_in_resource_document() {
        let app = Router::new().route(
            "/discovery",
            get(|| async { Json(as_doc("http://legacy.example.com")) }),
        );
        let base = serve(app).await;
        let found = discover_from_resource(
            &Client::new(),
            &format!("{base}/rpc"),
            Some(&format!("{base}/discovery")),
            false,
        )
        .await
        .unwrap();
        assert_eq!(found.metadata.issuer, "http://legacy.example.com");
    }

    #[tokio::test]
    async fn test_discovery_error_lists_tried_urls() {
        let base = serve(Router::new()).await;
        let err = discover_from_resource(&Client::new(), &format!("{base}/rpc"), None, false)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("/.well-known/oauth-protected-resource/rpc"),
            "{msg}"
        );
        assert!(msg.contains("404"), "{msg}");
    }

    #[tokio::test]
    async fn test_fetch_resource_name_best_effort() {
        let app = Router::new().route(
            "/.well-known/oauth-protected-resource",
            get(|| async { Json(json!({ "resource_name": "Named" })) }),
        );
        let base = serve(app).await;
        assert_eq!(
            fetch_resource_name(&Client::new(), &format!("{base}/rpc")).await,
            Some("Named".into())
        );
        let empty = serve(Router::new()).await;
        assert_eq!(fetch_resource_name(&Client::new(), &empty).await, None);
    }
}
