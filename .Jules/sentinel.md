## 2024-08-30 - [SSRF Mitigation Enhancement]
**Vulnerability:** Port Bypass in SSRF Prevention
**Learning:** `Url::host_str()` does not include the port. Validating the host alone allowed attackers to potentially hit different services running on the exact same host just by varying the port number in the URL.
**Prevention:** Check both `url.host_str()` and `url.port()` when implementing SSRF block lists or URL validators where the host is expected to be strictly matched against a known baseline.
## 2026-09-13 - [Secure Log Directory Permissions]\n**Vulnerability:** Insecure file permissions allowed local users to access tracing/log information.\n**Learning:** When using , the log directory must be explicitly created with secure permissions (e.g. ) prior to initialization to prevent data leakage.\n**Prevention:** Use  with  () during creation to safely set permissions.
## 2026-09-13 - [Secure Log Directory Permissions]
**Vulnerability:** Insecure file permissions allowed local users to access tracing/log information.
**Learning:** When using tracing_appender, the log directory must be explicitly created with secure permissions (e.g. 0o700) prior to initialization to prevent data leakage.
**Prevention:** Use std::fs::DirBuilder with std::os::unix::fs::DirBuilderExt (builder.mode(0o700)) during creation to safely set permissions.
