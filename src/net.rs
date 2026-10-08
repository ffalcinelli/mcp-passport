//! # URL security policy
//!
//! - Remote endpoints (MCP server, authorization server) must use HTTPS, except on
//!   loopback hosts or when the user explicitly allows insecure HTTP.
//! - The OAuth redirect URI must be a loopback `http` URI (RFC 8252 §7.3), so the
//!   callback server is never reachable from the network.

use crate::Result;
use anyhow::{bail, Context};
use std::net::IpAddr;
use tracing::warn;
use url::{Host, Url};

/// `localhost`, `127.0.0.0/8` or `::1`.
pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Requires `https`, or `http` on a loopback host. With `allow_insecure`, plain
/// `http` anywhere is accepted with a warning.
pub(crate) fn require_secure_url(url: &str, what: &str, allow_insecure: bool) -> Result<()> {
    let parsed = Url::parse(url).with_context(|| format!("Invalid {what} '{url}'"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&parsed) => Ok(()),
        "http" if allow_insecure => {
            warn!(
                "{} '{}' uses plain HTTP; tokens may be exposed (--allow-insecure-http).",
                what, url
            );
            Ok(())
        }
        "http" => bail!(
            "{what} '{url}' must use HTTPS (plain HTTP is only allowed for loopback hosts, \
             or with --allow-insecure-http)"
        ),
        other => bail!("{what} '{url}' has unsupported scheme '{other}'"),
    }
}

/// Requires an `http` redirect URI on a loopback host with an explicit port.
pub(crate) fn require_loopback_redirect(url: &str) -> Result<Url> {
    let parsed = Url::parse(url).with_context(|| format!("Invalid redirect URL '{url}'"))?;
    if parsed.scheme() != "http" || !is_loopback(&parsed) {
        bail!(
            "Redirect URL '{url}' must be an http URL on 127.0.0.1, [::1] or localhost \
             (RFC 8252 §7.3)"
        );
    }
    if parsed.port().is_none() {
        bail!("Redirect URL '{url}' must include a port");
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_loopback() {
        for u in [
            "http://localhost:1",
            "http://LOCALHOST",
            "http://127.0.0.1",
            "http://127.1.2.3",
            "http://[::1]:8080",
        ] {
            assert!(is_loopback(&Url::parse(u).unwrap()), "{u}");
        }
        for u in [
            "http://example.com",
            "http://10.0.0.1",
            "http://localhost.example.com",
            "http://0.0.0.0",
        ] {
            assert!(!is_loopback(&Url::parse(u).unwrap()), "{u}");
        }
    }

    #[test]
    fn test_require_secure_url() {
        assert!(require_secure_url("https://mcp.example.com/mcp", "x", false).is_ok());
        assert!(require_secure_url("http://127.0.0.1:8081/rpc", "x", false).is_ok());
        assert!(require_secure_url("http://localhost/rpc", "x", false).is_ok());
        let err = require_secure_url("http://mcp.example.com/mcp", "--remote-mcp-url", false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must use HTTPS"), "{err}");
        assert!(require_secure_url("http://mcp.example.com/mcp", "x", true).is_ok());
        assert!(require_secure_url("ftp://mcp.example.com", "x", true).is_err());
        assert!(require_secure_url("not a url", "x", true).is_err());
    }

    #[test]
    fn test_require_loopback_redirect() {
        assert!(require_loopback_redirect("http://127.0.0.1:8082/callback").is_ok());
        assert!(require_loopback_redirect("http://localhost:8082/callback").is_ok());
        assert!(require_loopback_redirect("http://[::1]:8082/callback").is_ok());
        assert!(require_loopback_redirect("http://0.0.0.0:8082/callback").is_err());
        assert!(require_loopback_redirect("http://192.168.1.2:8082/callback").is_err());
        assert!(require_loopback_redirect("https://127.0.0.1:8082/callback").is_err());
        assert!(require_loopback_redirect("http://127.0.0.1/callback").is_err());
        assert!(require_loopback_redirect("r").is_err());
    }
}
