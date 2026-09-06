## 2025-09-06 - [Prevent Config Secrets Leakage and Secure Log Directory]
**Vulnerability:** Potential local user log access and configuration secrets leakage via stdout/file logging.
**Learning:** By default, Rust's derived `Debug` trait prints all struct fields. If this contains sensitive data (e.g. `oidc_client_id`, `user_id` inside `Config`), standard logging mechanisms (like `tracing::info!("Config: {:?}", config)`) expose this to disk logs or stderr. In addition, logging directories like `/tmp/mcp-passport` might be generated with overly permissible default umask rules on Unix systems, exacerbating local access risks.
**Prevention:**
1. Replaced the `#[derive(Debug)]` attribute on the `Config` struct with a manual `std::fmt::Debug` block that selectively writes fields while explicitly writing `"***"` for sensitive configuration fields.
2. Leveraged `std::fs::DirBuilder` alongside `std::os::unix::fs::DirBuilderExt` to explicitly enforce a `0o700` restricted file permission when initializing log directories on Unix before handing off the handle to the log appender logic.
