# Contributing to mcp-passport

Thanks for your interest! Bug reports, feature requests, documentation fixes and code are all welcome.

## Getting started

1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/<you>/mcp-passport.git
   cd mcp-passport
   ```
2. Create a branch: `git checkout -b fix/short-description`.
3. Read [DEVELOPMENT.md](DEVELOPMENT.md) for the architecture and the test suites.

## Requirements

- **Rust 1.88** or later (the MSRV is checked in CI).
- A C compiler, and on Linux the OpenSSL development headers.
- **Docker**, only for the end-to-end suites.

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test                       # unit + integration suites, no Docker
./run_tests.sh --docker          # optional: also the Keycloak/Chrome suites
```

- Add tests for new behaviour and for bug fixes; a test that fails without the fix is the best kind.
- Use `Vault::in_memory` and `Timeouts::fast()` in tests; tests must never touch the real keychain or open a browser.
- Update the docs (README, GUIDE, CHANGELOG) when you change behaviour, flags or defaults.
- Keep commits focused, with messages that explain *why*.

## Reporting bugs

Please include your OS, the `mcp-passport --version` output, your MCP server and authorization server (and their versions, if known), the steps to reproduce, the expected and actual behaviour, and logs from `--log-level debug`. **Remove tokens and other secrets** before sharing logs.

Security issues: please don't open a public issue. See [SECURITY.md](SECURITY.md).

## Suggesting features

Describe the use case, how you'd expect it to work, and any spec (MCP, OAuth, OIDC) it relates to.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
