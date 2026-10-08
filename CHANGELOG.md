# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Upgrade notes
- Credentials are now stored per MCP server, so you will be asked to log in once more after upgrading.
- `--remote-sse-url` is optional and defaults to `--remote-mcp-url`.
- Plain-HTTP URLs on non-loopback hosts are refused unless `--allow-insecure-http` is set.
- The redirect URL must be a loopback `http` URL with a port.
- Logs moved from `/tmp/mcp-passport` to a private per-user directory (see `--log-dir`).
- A configured `--oidc-discovery-url` now takes precedence over the server's `resource_metadata`.
- macOS and Windows builds now really use the Keychain / Credential Manager. They previously fell back to keyring's non-persistent mock store. Linux persists through the Secret Service.
- Authorization servers must advertise PKCE S256 (`code_challenge_methods_supported`).
- `offline_access` is no longer requested unless `--oidc-offline-access` is set.
- `--mcp-protocol-version` is only a fallback: the version now comes from each message.

### Added
- Spec-compliant authorization server discovery: RFC 9728 Protected Resource Metadata, then RFC 8414 / OIDC Discovery, with `resource` and `issuer` validation. Legacy servers that serve AS metadata as their resource metadata keep working, with a warning.
- MCP Streamable HTTP: `Accept: application/json, text/event-stream`, SSE responses to POSTs, `202 Accepted`, session expiry (404), `Last-Event-ID` resumption, and a GET stream that stops cleanly on `405`.
- MCP 2026-07-28 (dual-era):
  - per-message protocol version;
  - `Mcp-Method` / `Mcp-Name` headers with base64-sentinel encoding;
  - `x-mcp-header` mirroring with invalid-tool filtering and a HeaderMismatch retry;
  - stdio cancellation by closing the response stream;
  - no GET stream or session ids for modern servers;
  - prompt exit when stdin closes.
- 2026-07-28 authorization:
  - exact issuer match and the PKCE check;
  - scope selection with step-up scope union;
  - issuer-bound credentials (`--oidc-issuer`);
  - Client ID Metadata Documents.
- Proactive refresh of tokens about to expire, and `dpop_jkt` in PAR requests.
- Tested against Keycloak 26.8.0, with an end-to-end suite on the 2026-07-28 spec.
- Silent refresh with DPoP-bound refresh tokens. A browser login is needed only when the refresh fails or more scopes are required.
- DPoP nonce support for the authorization server and the MCP server (RFC 9449 §8, §9).
- `--auth-timeout-secs`, `--allow-insecure-http`, and `Proxy::call()`.
- RFC 9207 `iss` validation and immediate handling of `error=` authorization responses.
- Initial project structure for `mcp-passport`.
- FAPI 2.0 (PAR + PKCE + DPoP) implementation.
- "Airlock" suspension mechanism for seamless authentication.
- Secure OS Vault integration via `keyring`.
- SSE (Server-Sent Events) support for remote MCP notifications.
- Integrated test suite using `testcontainers` and Keycloak.
- Dedicated stdout writer task for robust JSON-RPC communication.

### Changed
- Refactored `Proxy` to use `tokio::sync::watch` for efficient state management.
- Removed the `oauth2` and `once_cell` dependencies (PKCE and state are generated locally).
- The `resource_metadata` SSRF check compares full origins (scheme, host and port).
- Improved DPoP proof generation to include `ath` (access token hash) claim.

### Fixed
- Requests that fail now get a JSON-RPC error instead of leaving the client waiting forever. Invalid JSON gets a parse error.
- The `WWW-Authenticate` parser no longer matches parameter names inside other names or quoted values.
- The PAR authorization URL is properly percent-encoded. The DPoP `htu` drops query and fragment.
- A failed login no longer replaces the stored DPoP key.
- Concurrent requests rejected together share a single login, and tests no longer race on a global in-memory vault.
- A second login in the same run could hang: the browser reused a keep-alive connection to the previous login's callback server.
- Fixed security vulnerabilities in `rustls-webpki` and other dependencies.
- Resolved all `cargo clippy` and `cargo audit` warnings.
- Fixed potential output interleaving in high-concurrency scenarios.
