use clap::{Parser, ValueEnum};

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthScheme {
    #[default]
    Bearer,
    Dpop,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// Remote MCP server JSON-RPC endpoint
    #[arg(long, env = "MCP_PASSPORT_REMOTE_MCP_URL")]
    pub remote_mcp_url: String,

    /// Remote MCP server SSE endpoint
    #[arg(long, env = "MCP_PASSPORT_REMOTE_SSE_URL")]
    pub remote_sse_url: String,

    /// OIDC Discovery URL
    #[arg(long, env = "MCP_PASSPORT_OIDC_DISCOVERY_URL")]
    pub oidc_discovery_url: Option<String>,

    /// Keycloak OIDC Authorization URL (Override if not using discovery)
    #[arg(long, env = "MCP_PASSPORT_KC_AUTH_URL")]
    pub kc_auth_url: Option<String>,

    /// Keycloak OIDC Token URL (Override if not using discovery)
    #[arg(long, env = "MCP_PASSPORT_KC_TOKEN_URL")]
    pub kc_token_url: Option<String>,

    /// Keycloak OIDC Pushed Authorization Request (PAR) URL (Override if not using discovery)
    #[arg(long, env = "MCP_PASSPORT_KC_PAR_URL")]
    pub kc_par_url: Option<String>,

    /// OIDC Client ID
    #[arg(
        long,
        env = "MCP_PASSPORT_OIDC_CLIENT_ID",
        default_value = "mcp-passport"
    )]
    pub oidc_client_id: String,

    /// Local Loopback Redirect URL for OIDC
    #[arg(
        long,
        env = "MCP_PASSPORT_OIDC_REDIRECT_URL",
        default_value = "http://127.0.0.1:8082/callback"
    )]
    pub oidc_redirect_url: String,

    /// User ID for vault storage
    #[arg(long, env = "MCP_PASSPORT_USER_ID", default_value = "default_user")]
    pub user_id: String,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, env = "MCP_PASSPORT_LOG_LEVEL", default_value = "info")]
    pub log_level: String,

    /// MCP Protocol Version to include in headers
    #[arg(
        long,
        env = "MCP_PASSPORT_MCP_PROTOCOL_VERSION",
        default_value = "2025-11-25"
    )]
    pub mcp_protocol_version: String,

    /// Authorization header scheme (bearer or dpop)
    #[arg(long, env = "MCP_PASSPORT_AUTH_SCHEME", value_enum, default_value_t = AuthScheme::Bearer)]
    pub auth_scheme: AuthScheme,
}

impl Config {
    pub fn parse() -> Self {
        Parser::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parsing_minimal() {
        let args = vec![
            "mcp-passport",
            "--remote-mcp-url",
            "http://mcp/rpc",
            "--remote-sse-url",
            "http://mcp/sse",
            "--oidc-discovery-url",
            "http://kc/discovery",
        ];
        let config = Config::try_parse_from(args).unwrap();
        assert_eq!(config.remote_mcp_url, "http://mcp/rpc");
        assert_eq!(
            config.oidc_discovery_url,
            Some("http://kc/discovery".to_string())
        );
        assert_eq!(config.oidc_client_id, "mcp-passport");
        assert_eq!(config.user_id, "default_user");
        assert_eq!(config.mcp_protocol_version, "2025-11-25");
    }

    #[test]
    fn test_config_parsing_full() {
        let args = vec![
            "mcp-passport",
            "--remote-mcp-url",
            "http://mcp/rpc",
            "--remote-sse-url",
            "http://mcp/sse",
            "--kc-auth-url",
            "http://kc/auth",
            "--kc-token-url",
            "http://kc/token",
            "--kc-par-url",
            "http://kc/par",
            "--oidc-client-id",
            "custom-client",
            "--user-id",
            "custom-user",
            "--oidc-redirect-url",
            "http://localhost:9999/cb",
        ];
        let config = Config::try_parse_from(args).unwrap();
        assert_eq!(config.oidc_client_id, "custom-client");
        assert_eq!(config.user_id, "custom-user");
        assert_eq!(config.oidc_redirect_url, "http://localhost:9999/cb");
        assert_eq!(config.kc_auth_url, Some("http://kc/auth".to_string()));
    }

    #[test]
    fn test_config_missing_required() {
        let args = vec!["mcp-passport"];
        let result = Config::try_parse_from(args);
        assert!(result.is_err());
    }
}
