# mcp-passport development guide

Internals, build requirements and the test strategy. For the contribution workflow, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Architecture

```text
 AI client ── stdio ──▶ lib.rs (stdio loop) ──▶ proxy.rs (Proxy) ── HTTPS ──▶ MCP server
                │                                   │        ▲
                │ notifications/cancelled           │        │ 401 / 403
                ▼                                   ▼        │
          abort in-flight task               auth.rs (AuthManager) ──▶ authorization server
                                                    │
                                              vault.rs ──▶ OS keychain
```

| Module | Responsibility |
|--------|----------------|
| `lib.rs` | `run` / `run_with_vault`: config validation, the stdio read loop, a task per message, in-flight tracking for cancellation, JSON-RPC errors for failed requests, shutdown on stdin EOF (5s grace). |
| `main.rs` | CLI entry point: private log directory, tracing setup. |
| `proxy.rs` | `Proxy`: request building (MCP headers, DPoP proof), Streamable HTTP response handling (JSON, SSE, 202, 404), the airlock (`trigger_reauth`), DPoP nonces, proactive refresh, the legacy GET listener. |
| `mcp.rs` | Protocol eras (modern `_meta` vs legacy `initialize`), `Mcp-Method` / `Mcp-Name` headers, base64-sentinel header encoding, `x-mcp-header` validation and extraction. |
| `auth.rs` | `AuthManager`: endpoint resolution, PAR + PKCE + `dpop_jkt`, the loopback callback server (`state`, `iss`, `error`), code exchange and refresh with DPoP, scope selection, issuer binding. |
| `discovery.rs` | RFC 9728 protected resource metadata → RFC 8414 / OIDC metadata, with `resource` and exact `issuer` validation. |
| `challenge.rs` | `WWW-Authenticate` tokenizer (RFC 9110 §11.6.1). |
| `net.rs` | URL policy: HTTPS except on loopback, loopback-only redirect URIs. |
| `vault.rs` | Keychain (`keyring`) or in-memory storage for token, DPoP key, refresh token and credential metadata, scoped per MCP server. |
| `crypto.rs` | P-256 DPoP keys, proof JWTs (`htm`, `htu`, `ath`, `nonce`), RFC 7638 thumbprints. |
| `logging.rs` | Private (`0700`, no symlinks) log directory. |
| `config.rs` | CLI flags and environment variables (clap). |

### Protocol eras

A message whose `params._meta` carries `io.modelcontextprotocol/protocolVersion` is **modern** (2026-07-28). It is sent with its own version in `MCP-Protocol-Version`, plus `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*`, and never with a session id. Anything else is **legacy**: its version is the one requested by `initialize`, then the one the server negotiated; its session id is sent; and once a session exists, `listen_sse` opens the standalone GET stream.

`tools/list` results passing through are inspected (`Proxy::observe_response`). Each tool's `x-mcp-header` annotations are cached for later `tools/call`s, and tools with invalid annotations are removed. A `-32020 HeaderMismatch` triggers one `tools/list` refresh and one retry.

### The airlock

- `suspension_tx` (a `watch` channel) pauses outgoing requests while a re-authentication runs. Requests wait in `wait_for_airlock`.
- Every successful re-authentication bumps a **credential generation** (`reauth_count`). A rejected request passes the generation it used to `trigger_reauth`. If the generation has moved on, the result is reused; if an attempt failed meanwhile, its error is returned. So concurrent rejections share one login.
- `ReauthReason` picks the path:
  - `Unauthorized` refreshes first, then logs in;
  - `StepUp` always logs in;
  - `Expiring` only refreshes.
- A token from a browser login that is rejected within 5 seconds counts as a loop. A silent refresh is still allowed; another browser login is not.

### DPoP

Each login generates a new P-256 key. The key and the tokens are stored only after the code exchange succeeds. Every request carries a proof with `htm`, `htu` (no query or fragment), `ath` and, when the server asked for one, `nonce`. The PAR request sends the key's thumbprint as `dpop_jkt`, so the authorization code is bound to the key.

## Building

- **Rust 1.88+** (`rust-version` in `Cargo.toml`; CI checks it).
- A C compiler, and on Linux the OpenSSL development headers (`libssl-dev` / `openssl-devel`): `reqwest` uses the platform TLS stack (OpenSSL on Linux, the native stacks on macOS and Windows). `libdbus` is built from source (`keyring`'s `vendored` feature), and the keychain encryption uses `crypto-rust`.
- **Docker**, for the `--ignored` end-to-end suites (Keycloak 26.8.0, Selenium Chrome 4.49.0).

```bash
cargo build                 # debug
cargo build --release       # optimized
cargo doc --no-deps --open  # API docs
```

## Testing

| Suite | Needs | What it covers |
|-------|-------|----------------|
| `cargo test --lib` | nothing | Unit tests in every module. |
| `--test mock_oidc_test` | nothing | Airlock, discovery and re-auth against axum mocks. |
| `--test streamable_http_test` | nothing | Streamable HTTP behaviour, headers, `x-mcp-header`, nonce-free paths. |
| `--test refresh_test` | nothing | Silent and proactive refresh, PAR parameters. |
| `--test dpop_nonce_test` | nothing | DPoP nonces at the AS and the MCP server. |
| `--test spec_2026_test` | nothing | MCP 2026-07-28 conformance over real stdio, against the strict dual-era server in `tests/common/mcp_server.rs`. |
| `--test keycloak_2026_e2e_test -- --ignored` | Docker | Keycloak 26.8.0 + Chrome: discovery, PAR, login, `iss`, introspection-validated DPoP tokens, step-up, refresh rotation, subscriptions. |
| `--test integration_test`, `jdoe_login_test`, `agent_integration_test`, `headless_compliance_test` (all `--ignored`) | Docker | Older end-to-end flows with Keycloak and/or Chrome. |

`./run_tests.sh` runs formatting, clippy and the fast suites; `./run_tests.sh --docker` adds the Docker suites.

Test helpers:
- `Vault::in_memory` and `Timeouts::fast()` keep tests away from the real keychain and fast.
- `tests/common` has the pinned container images, `StdioClient` (drives `run_with_vault` like an MCP client), and the strict MCP server.
- `MCP_PASSPORT_TEST_KC_LOG_LEVEL` enables Keycloak debug logs in the Docker suites, which are dumped on failure.

`cargo bench --bench crate` measures DPoP signing and credential loading.

### Manual testing

`docker compose up` starts Keycloak (user `jdoe` / `password`) and the Python mock server in `mock-server/` on ports 8080 and 8081. `settings.json` and `example/.gemini/settings.json` are client configurations for it.

## Rules of the road

- Never log tokens, keys, codes or refresh tokens.
- Store credentials only through `Vault`, and keep them scoped per MCP server and bound to their issuer.
- Treat remote input (challenges, metadata, tool schemas) as untrusted: validate origins, issuers and formats before acting on it.
- Keep `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and the fast suites green.
