use clap::Parser;
use mcp_passport::config::Config;

#[test]
fn test_cli_parsing() {
    let args = vec![
        "mcp-passport",
        "--remote-mcp-url", "http://localhost:8080",
        "--remote-sse-url", "http://localhost:8080/sse",
        "--user-id", "test-user",
        "--oidc-client-id", "test-client",
        "--oidc-redirect-url", "http://localhost:8081/callback",
    ];
    let config = Config::try_parse_from(args).unwrap();
    assert_eq!(config.remote_mcp_url, "http://localhost:8080");
    assert_eq!(config.user_id, "test-user");
    assert_eq!(config.oidc_client_id, "test-client");
}

#[test]
fn test_cli_parsing_missing_arg() {
    let args = vec!["mcp-passport"];
    let result = Config::try_parse_from(args);
    assert!(result.is_err());
}
