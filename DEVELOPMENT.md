# mcp-passport: Development Guide 🛠️

This document provides technical details for developers looking to contribute to or understand the internals of `mcp-passport`.

## 🏗️ Architecture Deep Dive

### 1. The Transparent Layer 7 Bridge
The core of `mcp-passport` is a bi-directional bridge between the AI client's `stdio` and the remote server's HTTP/SSE interface.
- **Stdio Loop**: Managed in `src/main.rs`, it reads lines from `stdin`, spawns `tokio` tasks to handle individual JSON-RPC requests via the `Proxy`.
- **SSE Listener**: A persistent background task (`Proxy::listen_sse`) that uses `reqwest-eventsource` to pipe server notifications back to `stdout`.

### 2. The "Airlock" State Machine
To handle authentication without breaking the AI client's connection, we use a suspension mechanism:
- **`tokio::sync::watch`**: This channel broadcasts the "suspended" state.
- When a `401 Unauthorized` is detected, the `Proxy` triggers `reauthenticate` and flips the switch.
- All subsequent and current requests wait on `wait_for_airlock()` until the switch is flipped back.

### 3. FAPI 2.0 & DPoP Implementation
- **PAR (Pushed Authorization Requests)**: We perform a POST to the OIDC provider's PAR endpoint to exchange authorization parameters for a `request_uri`. This enhances security by keeping parameters out of the browser history.
- **DPoP (RFC 9449)**: 
    - Every request includes a `DPoP` header containing a JWT.
    - The JWT is signed with an ephemeral P-256 key (`src/crypto.rs`).
    - The JWT includes `htm` (HTTP Method), `htu` (HTTP URL), and `ath` (Access Token Hash) claims to cryptographically bind the token to the specific request.

### 4. Secure Vault
We use the `keyring` crate to interface with:
- **macOS**: Keychain
- **Windows**: Credential Manager
- **Linux**: Secret Service (libsecret) or KWallet.

## 🚀 Development Setup

### Prerequisites
- **Rust**: 1.75+
- **Docker**: Required for running integration tests via `testcontainers`.
- **OpenSSL**: System headers required for `keyring` on some Linux distributions.

### Build & Run
```bash
# Debug build
cargo build

# Run with environment variables
export MCP_PASSPORT_REMOTE_MCP_URL="http://localhost:8081/rpc"
export MCP_PASSPORT_REMOTE_SSE_URL="http://localhost:8081/sse"
# ... other vars
./target/debug/mcp-passport
```

## 🧪 Testing Strategy

### Unit Tests
Located within the source files (e.g., `src/crypto.rs`, `src/vault.rs`). Focus on isolated logic.
```bash
cargo test --lib
```

### Mocked Integration Tests
`tests/mock_oidc_test.rs` uses `axum` to mock both the OIDC provider and the MCP server. This allows for extremely fast testing of the "Airlock" and re-authentication logic without external dependencies.
```bash
cargo test --test mock_oidc_test
```

### Full Integration Tests
`tests/integration_test.rs` uses `testcontainers` to spin up a real **Keycloak** instance. This verifies compatibility with a production-grade FAPI 2.0 implementation.
```bash
cargo test --test integration_test
```

## 🛡️ Security Standards
- **No Plaintext Secrets**: Never print, log, or store tokens in plain files.
- **Ephemeral Keys**: DPoP keys should be rotated frequently (the proxy rotates them on every re-authentication).
- **Zero-Trust Proxying**: The proxy must not inspect or store JSON-RPC payloads beyond basic validation for `id` presence.

## 📜 Code Style
- Follow `cargo fmt`.
- Use `clippy` for linting: `cargo clippy -- -D warnings`.
- Document public methods with doc comments.
