# Agent context: mcp-passport

## Project Overview
`mcp-passport` is a high-performance, secure Layer 7 proxy for the **Model Context Protocol (MCP)**. It acts as a dedicated bridge between an AI client (e.g., Claude Desktop, Gemini CLI) communicating via `stdio` and a remote MCP server over HTTPS.

The project is built on five core architectural pillars:
1. **Transparent L7 Bridge**: 1:1 multiplexing of JSON-RPC over `stdio` ↔ HTTP, including persistent SSE piping for server-originated notifications.
2. **MCP 2026-07-28, dual-era**: Modern (per-request `_meta`) and legacy (`initialize`, up to 2025-11-25) clients are both forwarded with the HTTP rules of their era. Implements the 2026-07-28 authorization specification: discovery, PKCE check, `iss`, scope selection and step-up, issuer binding, Client ID Metadata Documents.
3. **The "Airlock" State Machine**: Non-destructive interception of 401 (expiration) and 403 (insufficient scope) challenges, suspending the request stream using `tokio::sync::watch` while triggering transparent OIDC flows.
4. **FAPI 2.0 Security**: Financial-grade security implementing **Pushed Authorization Requests (PAR)**, **PKCE**, and **DPoP (Demonstrating Proof-of-Possession)** to cryptographically bind tokens to ephemeral keys.
5. **OS-Native Vault**: Secure storage of sensitive tokens and DPoP keys using the system's native keychain (macOS Keychain, Windows Credential Manager, Linux keyutils backed by the Secret Service) via the `keyring` crate. All three native backends must stay enabled in `Cargo.toml`: without a backend feature keyring silently uses a non-persistent mock store.

## Implementation Details
- **Lazy Auth Flow**: `AuthManager` is initialized lazily upon discovering the authorization server's metadata from the remote MCP server.
- **Dynamic Discovery**: `src/discovery.rs` fetches RFC 9728 Protected Resource Metadata (from a challenge's validated `resource_metadata`, or the path-inserted/root `.well-known/oauth-protected-resource`), then RFC 8414 / OIDC metadata of `authorization_servers[0]`, validating `resource` and `issuer`. Precedence: `--kc-*-url` overrides, then `--oidc-discovery-url`, then dynamic discovery.
- **Airlock generations**: `Proxy::trigger_reauth` takes the credential generation the rejected request used, so concurrent rejections share one attempt; 401 tries a refresh first, 403 step-up always logs in.
- **MCP eras** (`src/mcp.rs`): a message with `_meta.io.modelcontextprotocol/protocolVersion` is modern (2026-07-28): it gets `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` headers, no session id, and stdio cancellation is translated into closing its response stream. Anything else is legacy (initialize, sessions, GET stream).
- **Refresh & DPoP nonces**: refresh tokens are stored per server and redeemed with the bound DPoP key; `DPoP-Nonce` / `use_dpop_nonce` are handled for both the AS and the MCP server.
- **Resource Signaling**: Includes the MCP server URL as the `resource` parameter in PAR and Token requests (RFC 8707).
- **Flexible Headers**: Supports both `Bearer` (MCP default) and `DPoP` authorization schemes via the `--auth-scheme` flag.
- **SSE Piping**: Persistent listener in `src/proxy.rs` that maintains a DPoP-signed stream and handles re-authentication transparently.

## Directory Structure & Key Files
- `src/main.rs`: Entry point and logging setup.
- `src/mcp.rs`: Protocol eras, `Mcp-*` headers, `x-mcp-header` validation.
- `src/config.rs`: CLI flags and environment variables.
- `src/lib.rs`: `run`/`run_with_vault`, config validation, stdio loop, JSON-RPC error responses.
- `src/proxy.rs`: Request suspension (Airlock), Streamable HTTP handling, and SSE listener.
- `src/auth.rs`: PAR flow, loopback callback (`state`/`iss`/`error` checks), DPoP token exchange and refresh.
- `src/discovery.rs`: RFC 9728 → RFC 8414 authorization server discovery.
- `src/challenge.rs`: `WWW-Authenticate` tokenizer.
- `src/net.rs`: HTTPS / loopback URL policy.
- `src/logging.rs`: Private log directory setup.
- `src/vault.rs`: `keyring` abstraction (or in-memory store) for tokens, refresh tokens and keys, isolated per MCP server.
- `src/crypto.rs`: DPoP implementation (ES256 key generation and JWT signing).

## Testing and Quality Assurance
- **Headless Compliance Tests**: 
    - `tests/headless_compliance_test.rs`: Full E2E flow using **Fantoccini** and **Selenium/Chrome** to automate OIDC login against a mock server.
- **Integration Tests**: 
    - `tests/integration_test.rs`: End-to-end flow with a live Keycloak instance via `testcontainers`.
- **Mock Tests** (no Docker needed):
    - `tests/mock_oidc_test.rs`: Fast-feedback tests for protocol-level logic.
    - `tests/streamable_http_test.rs`, `tests/refresh_test.rs`, `tests/dpop_nonce_test.rs`: transport, refresh and nonce behaviour.
    - `tests/spec_2026_test.rs`: MCP 2026-07-28 conformance over the real stdio path against `tests/common/mcp_server.rs`, a strict dual-era server.
    - Use `Vault::in_memory(..)` and `Timeouts::fast()` in tests; never touch the real keychain.
- **Keycloak**: Docker suites pin Keycloak 26.8.0 and Selenium 4.49.0 in `tests/common/mod.rs`. `tests/keycloak_2026_e2e_test.rs` is the full end-to-end check.

## Key Commands
- **Everything fast**: `./run_tests.sh` (fmt, clippy, `cargo test`); `./run_tests.sh --docker` adds the end-to-end suites.
- **Spec conformance**: `cargo test --test spec_2026_test`
- **Keycloak E2E**: `cargo test --test keycloak_2026_e2e_test -- --ignored --nocapture`
- **Coverage**: `cargo tarpaulin --out Xml --verbose` (integrated with [Codecov](https://app.codecov.io/gh/ffalcinelli/mcp-passport))
- **MSRV**: Rust 1.88 (`rust-version` in `Cargo.toml`, checked in CI).

## Docs
- `README.md` (overview, configuration table, which must match `--help`), `GUIDE.md` (setup and troubleshooting), `DEVELOPMENT.md` (architecture), `SECURITY.md` (threat model), `CHANGELOG.md`.
- `site/` is the GitHub Pages landing page; `.github/workflows/docs.yml` deploys it next to the versioned rustdoc.
