# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Upgrade notes
- **Log in once more**: credentials are now stored per MCP server and bound to the issuer that granted them.
- **macOS and Windows** now really use the Keychain / Credential Manager. Builds previously fell back to keyring's non-persistent mock store, so stored tokens were never found. **Linux** persists through the Secret Service, with a kernel-keyring cache.
- Authorization servers must advertise PKCE S256 (`code_challenge_methods_supported`), as the MCP spec requires.
- Plain-HTTP URLs on non-loopback hosts are refused unless `--allow-insecure-http` is set. The redirect URL must be a loopback `http` URL with a port.
- A configured `--oidc-discovery-url` now takes precedence over the server's `resource_metadata`.
- `offline_access` is only requested with `--oidc-offline-access`.
- `--remote-sse-url` is optional (it defaults to `--remote-mcp-url`) and only used for legacy servers. `--mcp-protocol-version` is only a fallback: each message determines its own version.
- Logs moved from `/tmp/mcp-passport` to a private per-user directory (see `--log-dir`).
- Rust 1.88 or later is required.

### Added
- **MCP 2026-07-28, dual-era**:
  - modern and legacy clients are both forwarded with the rules of their era;
  - the `MCP-Protocol-Version` (per message), `Mcp-Method` and `Mcp-Name` headers, with the base64 sentinel encoding;
  - `x-mcp-header` → `Mcp-Param-*` mirroring, invalid-tool filtering and a HeaderMismatch retry;
  - stdio `notifications/cancelled` closes the request's response stream;
  - `subscriptions/listen` passthrough;
  - no GET stream or session ids for modern servers.
- **Streamable HTTP**:
  - `Accept: application/json, text/event-stream`;
  - SSE responses to POSTs, `202 Accepted`, JSON-RPC error bodies of non-2xx replies;
  - for legacy servers: session expiry (404), `Last-Event-ID` resumption, and a GET stream that stops cleanly on 405.
- **Discovery**: RFC 9728 protected resource metadata, then RFC 8414 / OIDC metadata, with `resource` and exact `issuer` validation. Servers that serve AS metadata as their resource metadata keep working, with a warning.
- **Authorization (2026-07-28 rules)**:
  - PKCE check;
  - scope selection from the challenge or `scopes_supported`, with scope union on step-up;
  - RFC 9207 `iss` validation, and immediate failure on `error=` responses;
  - issuer-bound credentials and `--oidc-issuer`;
  - Client ID Metadata Documents as client IDs.
- **Tokens**:
  - silent refresh with DPoP-bound refresh tokens, also proactively before expiry;
  - DPoP nonces from the authorization server and the MCP server;
  - `dpop_jkt` in PAR requests.
- New flags: `--auth-timeout-secs`, `--allow-insecure-http`, `--oidc-issuer`, `--oidc-offline-access`.
- `Proxy::call()` and `run_with_vault()` for library use.
- Tests:
  - a strict dual-era MCP 2026-07-28 test server and conformance suite;
  - an end-to-end suite against Keycloak 26.8.0 with headless Chrome;
  - benchmarks of the request hot paths.
- A landing page on GitHub Pages, next to the versioned API docs.
- Baseline:
  - FAPI 2.0 flow (PAR + PKCE + DPoP);
  - the airlock that suspends requests during re-authentication;
  - OS keychain storage;
  - SSE support;
  - a dedicated stdout writer;
  - Keycloak integration tests.

### Changed
- The airlock is driven by a credential generation: concurrent rejections share one login, and a fresh token rejected right away is reported as a loop. A silent refresh is still tried; another browser login is not.
- The MCP server, discovery URL and AS endpoints must use HTTPS except on loopback.
- The `resource_metadata` SSRF check compares full origins (scheme, host and port).
- Removed the `oauth2` and `once_cell` dependencies; PKCE and state are generated locally.
- Configurable timeouts replace test-only code paths.
- Tests use injectable in-memory vaults instead of a global store.

### Fixed
- Failed requests get a JSON-RPC error instead of leaving the client waiting forever. Invalid JSON gets a parse error.
- A second login in the same run could hang: the browser reused a keep-alive connection to the previous login's callback server.
- A failed login no longer replaces the stored DPoP key.
- The `WWW-Authenticate` parser no longer matches parameter names inside other names or quoted values.
- The PAR authorization URL is percent-encoded, and the DPoP `htu` drops query and fragment.
- `docker compose`: Keycloak's issuer URL is pinned, so backchannel introspection validates browser-issued tokens.
- Earlier fixes: output interleaving under concurrency, and dependency advisories (`rustls-webpki` and others).

### Security
- Credentials are scoped per MCP server and bound to their issuer. Refresh tokens are never sent to another authorization server.
- The log directory is private (`0700`) and may not be a symlink or owned by another user.
- The login callback listens on loopback only, and checks `state` and `iss`.
