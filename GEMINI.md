# Gemini Project Context: mcp-passport 🛡️

## Project Overview
`mcp-passport` is a high-performance, secure Layer 7 proxy for the **Model Context Protocol (MCP)**. It acts as a dedicated bridge between an AI client (e.g., Claude Desktop, Gemini CLI) communicating via `stdio` and a remote MCP server over HTTPS.

The project is built on five core architectural pillars:
1. **Transparent L7 Bridge**: 1:1 multiplexing of JSON-RPC over `stdio` ↔ HTTP, including persistent SSE piping for server-originated notifications.
2. **Strict Spec Compliance**: Opaque pass-through of MCP payloads (spec 2025-11-25) without mutation or eager deserialization.
3. **The "Airlock" State Machine**: Non-destructive interception of 401 challenges, suspending the request stream using `tokio::sync::watch` while triggering transparent OIDC flows.
4. **FAPI 2.0 Security**: Financial-grade security implementing **Pushed Authorization Requests (PAR)**, **PKCE**, and **DPoP (Demonstrating Proof-of-Possession)** to cryptographically bind tokens to ephemeral keys.
5. **OS-Native Vault**: Secure storage of sensitive tokens and DPoP keys using the system's native keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) via the `keyring` crate.

## Implementation Details
- **Auth Flow**: Uses the `oauth2` crate and `axum` for the local loopback server (`127.0.0.1:8082`). Supports OIDC Discovery.
- **Proxy**: Core logic in `src/proxy.rs` handles the "Airlock" suspension and SSE piping.
- **Crypto**: `src/crypto.rs` manages P-256 keypairs and generates DPoP Proof JWTs (RFC 9449).
- **Vault Isolation**: Uses unique service names in `keyring` to ensure test isolation and protect primary credentials.

## Directory Structure & Key Files
- `src/main.rs`: Entry point, configuration parsing, and task orchestration.
- `src/proxy.rs`: Request suspension, HTTP proxying, and SSE listener.
- `src/auth.rs`: OIDC Discovery, PAR flow, and callback server.
- `src/vault.rs`: `keyring` abstraction for tokens and keys.
- `src/crypto.rs`: DPoP implementation (ES256).

## Testing and Quality Assurance
- **Integration Tests**: 
    - `tests/integration_test.rs`: End-to-end flow with a live Keycloak instance via `testcontainers`.
    - `tests/mock_oidc_test.rs`: Automated fast-feedback tests with mocked OIDC and MCP servers.
- **Coverage**: Target >90% coverage using `cargo-tarpaulin`.

## Key Commands
- **Test All**: `cargo test`
- **Integration Only**: `cargo test --test integration_test`
- **Coverage**: `cargo tarpaulin --ignore-config --ignore-tests -v`
