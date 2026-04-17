# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure for `mcp-passport`.
- FAPI 2.0 (PAR + PKCE + DPoP) implementation.
- "Airlock" suspension mechanism for seamless authentication.
- Secure OS Vault integration via `keyring`.
- SSE (Server-Sent Events) support for remote MCP notifications.
- Integrated test suite using `testcontainers` and Keycloak.
- Dedicated stdout writer task for robust JSON-RPC communication.

### Changed
- Refactored `Proxy` to use `tokio::sync::watch` for efficient state management.
- Updated `oauth2` to version 5.0.0 for improved security and `reqwest` 0.12 support.
- Improved DPoP proof generation to include `ath` (access token hash) claim.

### Fixed
- Fixed security vulnerabilities in `rustls-webpki` and other dependencies.
- Resolved all `cargo clippy` and `cargo audit` warnings.
- Fixed potential output interleaving in high-concurrency scenarios.
