# Contributing to mcp-passport 🛡️

Thank you for your interest in contributing to `mcp-passport`! We welcome contributions of all kinds, from bug reports and feature requests to code changes and documentation improvements.

## 🚀 Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/your-username/mcp-passport.git
    cd mcp-passport
    ```
3.  **Create a new branch** for your work:
    ```bash
    git checkout -b feature/my-new-feature
    ```

## 🛠️ Development Workflow

### Prerequisites
-   **Rust**: 1.75 or later.
-   **Docker**: Required for running integration tests via `testcontainers`.

### Standards & Quality
We maintain high standards for code quality:
-   **Formatting**: Always run `cargo fmt` before committing.
-   **Linting**: Check for warnings with `cargo clippy -- -D warnings`.
-   **Testing**: Ensure all tests pass with `cargo test`.
    -   For E2E tests: `cargo test --test headless_compliance_test`.

### Pull Request Process
1.  **Update documentation** if you're adding or changing features.
2.  **Add tests** for any new functionality or bug fixes.
3.  **Ensure CI passes** on your pull request.
4.  **Wait for review**: A maintainer will review your PR and may suggest changes.

## 🐛 Reporting Bugs
When reporting a bug, please include:
-   Your operating system and Rust version.
-   Steps to reproduce the issue.
-   Expected vs. actual behavior.
-   Any relevant logs (run with `RUST_LOG=debug`).

## 💡 Suggesting Features
We're always looking for ways to improve! When suggesting a feature:
-   Explain the use case and why it's valuable.
-   Provide examples of how it would work.

## 📜 License
By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
