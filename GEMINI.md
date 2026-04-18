# Gemini Project Context: mcp-passport 🛡️

## Project Overview
`mcp-passport` is a high-performance, secure Layer 7 proxy for the **Model Context Protocol (MCP)**. It acts as a dedicated bridge between an AI client (e.g., Claude Desktop, Gemini CLI) communicating via `stdio` and a remote MCP server over HTTPS.

The project is built on five core architectural pillars:
1. **Transparent L7 Bridge**: 1:1 multiplexing of JSON-RPC over `stdio` ↔ HTTP, including persistent SSE piping for server-originated notifications.
2. **MCP Spec Compliance (2025-11-25)**: Full implementation of the MCP authorization specification, including dynamic discovery via `WWW-Authenticate` and RFC 8707 Resource Indicators.
3. **The "Airlock" State Machine**: Non-destructive interception of 401 (expiration) and 403 (insufficient scope) challenges, suspending the request stream using `tokio::sync::watch` while triggering transparent OIDC flows.
4. **FAPI 2.0 Security**: Financial-grade security implementing **Pushed Authorization Requests (PAR)**, **PKCE**, and **DPoP (Demonstrating Proof-of-Possession)** to cryptographically bind tokens to ephemeral keys.
5. **OS-Native Vault**: Secure storage of sensitive tokens and DPoP keys using the system's native keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) via the `keyring` crate.

## Implementation Details
- **Lazy Auth Flow**: `AuthManager` is initialized lazily upon discovering the authorization server's metadata from the remote MCP server.
- **Dynamic Discovery**: Implements logic in `src/proxy.rs` to parse `resource_metadata` from 401 challenges or fallback to `.well-known/oauth-protected-resource`.
- **Resource Signaling**: Includes the MCP server URL as the `resource` parameter in PAR and Token requests (RFC 8707).
- **Flexible Headers**: Supports both `Bearer` (MCP default) and `DPoP` authorization schemes via the `--auth-scheme` flag.
- **SSE Piping**: Persistent listener in `src/proxy.rs` that maintains a DPoP-signed stream and handles re-authentication transparently.

## Directory Structure & Key Files
- `src/main.rs`: Entry point, configuration, and task orchestration.
- `src/proxy.rs`: Request suspension (Airlock), dynamic discovery logic, and SSE listener.
- `src/auth.rs`: OIDC Discovery, PAR flow, manual DPoP token exchange, and callback server.
- `src/vault.rs`: `keyring` abstraction for tokens and keys with service-level isolation.
- `src/crypto.rs`: DPoP implementation (ES256 key generation and JWT signing).

## Testing and Quality Assurance
- **Headless Compliance Tests**: 
    - `tests/headless_compliance_test.rs`: Full E2E flow using **Fantoccini** and **Selenium/Chrome** to automate OIDC login against a mock server.
- **Integration Tests**: 
    - `tests/integration_test.rs`: End-to-end flow with a live Keycloak instance via `testcontainers`.
- **Mock Tests**:
    - `tests/mock_oidc_test.rs`: Fast-feedback tests for protocol-level logic.

## Key Commands
- **Test All**: `cargo test`
- **Compliance E2E**: `cargo test --test headless_compliance_test`
- **Integration Only**: `cargo test --test integration_test`
- **Coverage**: `cargo tarpaulin --out Xml --verbose` (Integrated with [Codecov](https://app.codecov.io/gh/ffalcinelli/mcp-passport))
