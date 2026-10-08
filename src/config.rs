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
    #[arg(
        long,
        env = "MCP_PASSPORT_REMOTE_MCP_URL",
        help_heading = "Server Configuration"
    )]
    pub remote_mcp_url: String,

    /// Remote MCP server SSE endpoint (defaults to --remote-mcp-url, as in Streamable HTTP)
    #[arg(
        long,
        env = "MCP_PASSPORT_REMOTE_SSE_URL",
        help_heading = "Server Configuration"
    )]
    pub remote_sse_url: Option<String>,

    /// MCP Protocol Version to include in headers
    #[arg(
        long,
        env = "MCP_PASSPORT_MCP_PROTOCOL_VERSION",
        default_value = "2025-11-25",
        help_heading = "Server Configuration"
    )]
    pub mcp_protocol_version: String,

    /// Authorization header scheme (bearer or dpop)
    #[arg(
        long,
        env = "MCP_PASSPORT_AUTH_SCHEME",
        value_enum,
        default_value_t = AuthScheme::Bearer,
        help_heading = "Server Configuration"
    )]
    pub auth_scheme: AuthScheme,

    /// OIDC Discovery URL
    #[arg(
        long,
        env = "MCP_PASSPORT_OIDC_DISCOVERY_URL",
        help_heading = "OIDC Configuration"
    )]
    pub oidc_discovery_url: Option<String>,

    /// Keycloak OIDC Authorization URL (Override if not using discovery)
    #[arg(
        long,
        env = "MCP_PASSPORT_KC_AUTH_URL",
        help_heading = "OIDC Configuration"
    )]
    pub kc_auth_url: Option<String>,

    /// Keycloak OIDC Token URL (Override if not using discovery)
    #[arg(
        long,
        env = "MCP_PASSPORT_KC_TOKEN_URL",
        help_heading = "OIDC Configuration"
    )]
    pub kc_token_url: Option<String>,

    /// Keycloak OIDC Pushed Authorization Request (PAR) URL (Override if not using discovery)
    #[arg(
        long,
        env = "MCP_PASSPORT_KC_PAR_URL",
        help_heading = "OIDC Configuration"
    )]
    pub kc_par_url: Option<String>,

    /// Expected issuer of the authorization server the client ID is registered with
    #[arg(
        long,
        env = "MCP_PASSPORT_OIDC_ISSUER",
        help_heading = "OIDC Configuration"
    )]
    pub oidc_issuer: Option<String>,

    /// OIDC Client ID (a pre-registered ID, or an https URL of a Client ID Metadata Document)
    #[arg(
        long,
        env = "MCP_PASSPORT_OIDC_CLIENT_ID",
        default_value = "mcp-passport",
        help_heading = "OIDC Configuration"
    )]
    pub oidc_client_id: String,

    /// Local Loopback Redirect URL for OIDC
    #[arg(
        long,
        env = "MCP_PASSPORT_OIDC_REDIRECT_URL",
        default_value = "http://127.0.0.1:8082/callback",
        help_heading = "Local State"
    )]
    pub oidc_redirect_url: String,

    /// User ID for vault storage
    #[arg(
        long,
        env = "MCP_PASSPORT_USER_ID",
        default_value = "default_user",
        help_heading = "Local State"
    )]
    pub user_id: String,

    /// Seconds to wait for the browser login to complete before giving up
    #[arg(
        long,
        env = "MCP_PASSPORT_AUTH_TIMEOUT_SECS",
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..),
        help_heading = "Local State"
    )]
    pub auth_timeout_secs: u64,

    /// Directory containing success.html and failure.html for the auth callback
    #[arg(long, env = "MCP_PASSPORT_TEMPLATE_DIR", help_heading = "Local State")]
    pub template_dir: Option<std::path::PathBuf>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(
        long,
        env = "MCP_PASSPORT_LOG_LEVEL",
        default_value = "info",
        help_heading = "Logging"
    )]
    pub log_level: String,

    /// Directory for logs [default: per-user state directory, e.g. ~/.local/state/mcp-passport/logs]
    #[arg(long, env = "MCP_PASSPORT_LOG_DIR", help_heading = "Logging")]
    pub log_dir: Option<std::path::PathBuf>,

    /// Allow plain-HTTP MCP and authorization server URLs on non-loopback hosts (insecure)
    #[arg(
        long,
        env = "MCP_PASSPORT_ALLOW_INSECURE_HTTP",
        help_heading = "Server Configuration"
    )]
    pub allow_insecure_http: bool,
}

impl Config {
    pub fn parse() -> Self {
        Parser::parse()
    }

    /// The log directory: `--log-dir`, or a private per-user directory.
    pub fn resolved_log_dir(&self) -> std::path::PathBuf {
        self.log_dir.clone().unwrap_or_else(default_log_dir)
    }
}

/// `$XDG_STATE_HOME/mcp-passport/logs` on Linux, the local data directory on
/// macOS and Windows, and a per-user temp directory as a last resort.
pub fn default_log_dir() -> std::path::PathBuf {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .map(|d| d.join("mcp-passport").join("logs"))
        .unwrap_or_else(|| std::env::temp_dir().join("mcp-passport"))
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
        assert_eq!(config.auth_timeout_secs, 300);
    }

    #[test]
    fn test_config_auth_timeout() {
        let base = [
            "mcp-passport",
            "--remote-mcp-url",
            "http://mcp/rpc",
            "--remote-sse-url",
            "http://mcp/sse",
        ];
        let config =
            Config::try_parse_from(base.iter().chain(&["--auth-timeout-secs", "42"])).unwrap();
        assert_eq!(config.auth_timeout_secs, 42);

        let zero = Config::try_parse_from(base.iter().chain(&["--auth-timeout-secs", "0"]));
        assert!(zero.is_err());
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
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn test_config_invalid_enum_value() {
        let args = vec![
            "mcp-passport",
            "--remote-mcp-url",
            "http://mcp/rpc",
            "--remote-sse-url",
            "http://mcp/sse",
            "--auth-scheme",
            "invalid",
        ];
        let result = Config::try_parse_from(args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::InvalidValue
        );
    }

    #[test]
    fn test_config_unknown_argument() {
        let args = vec![
            "mcp-passport",
            "--remote-mcp-url",
            "http://mcp/rpc",
            "--remote-sse-url",
            "http://mcp/sse",
            "--unknown-arg",
            "value",
        ];
        let result = Config::try_parse_from(args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn test_config_missing_value() {
        let args = vec![
            "mcp-passport",
            "--remote-mcp-url",
            "http://mcp/rpc",
            "--remote-sse-url",
            "http://mcp/sse",
            "--oidc-client-id", // Missing value
        ];
        let result = Config::try_parse_from(args);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::InvalidValue
        );
    }
}
