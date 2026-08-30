## 2024-08-30 - [SSRF Mitigation Enhancement]
**Vulnerability:** Port Bypass in SSRF Prevention
**Learning:** `Url::host_str()` does not include the port. Validating the host alone allowed attackers to potentially hit different services running on the exact same host just by varying the port number in the URL.
**Prevention:** Check both `url.host_str()` and `url.port()` when implementing SSRF block lists or URL validators where the host is expected to be strictly matched against a known baseline.
