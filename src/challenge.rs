//! # `WWW-Authenticate` parsing
//!
//! A small tokenizer for the challenge grammar of RFC 9110 §11.6.1:
//!
//! ```text
//! challenge  = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
//! auth-param = token BWS "=" BWS ( token / quoted-string )
//! ```
//!
//! Parameter names are matched whole and case-insensitively, quoted strings
//! honour `\` escapes, and several challenges (in one header or across several
//! header lines) are supported.

use reqwest::header::{HeaderMap, WWW_AUTHENTICATE};
use tracing::debug;

/// A single authentication challenge, e.g. `DPoP error="use_dpop_nonce"`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub scheme: String,
    pub params: Vec<(String, String)>,
}

impl Challenge {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The parameters of the `WWW-Authenticate` header(s) that mcp-passport acts on.
#[derive(Debug, Default)]
pub(crate) struct WwwAuthenticate {
    pub challenges: Vec<Challenge>,
}

impl WwwAuthenticate {
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut challenges = Vec::new();
        for value in headers.get_all(WWW_AUTHENTICATE) {
            match value.to_str() {
                Ok(v) => {
                    debug!("Parsing WWW-Authenticate: {}", v);
                    challenges.extend(parse_challenges(v));
                }
                Err(_) => debug!("Ignoring non-ASCII WWW-Authenticate header"),
            }
        }
        Self { challenges }
    }

    /// The first value of `name` across all challenges.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.challenges.iter().find_map(|c| c.param(name))
    }

    pub fn resource_metadata(&self) -> Option<&str> {
        self.param("resource_metadata")
    }

    pub fn error(&self) -> Option<&str> {
        self.param("error")
    }

    /// The space-separated `scope` parameter, split into scopes.
    pub fn scope(&self) -> Option<Vec<String>> {
        self.param("scope")
            .map(|s| s.split_whitespace().map(str::to_string).collect())
    }
}

fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && is_ws(b[i]) {
        i += 1;
    }
    i
}

/// Parses one header value into its challenges. Malformed input stops the
/// parse; whatever was parsed before is kept.
pub(crate) fn parse_challenges(header: &str) -> Vec<Challenge> {
    let b = header.as_bytes();
    let mut out: Vec<Challenge> = Vec::new();
    let mut i = 0;

    loop {
        while i < b.len() && (is_ws(b[i]) || b[i] == b',') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }

        let start = i;
        while i < b.len() && !is_ws(b[i]) && b[i] != b',' && b[i] != b'=' {
            i += 1;
        }
        let token = &header[start..i];

        let j = skip_ws(b, i);
        if token.is_empty() || j >= b.len() || b[j] != b'=' {
            // A bare token starts a new challenge (or is a token68, which we ignore).
            if !token.is_empty() {
                out.push(Challenge {
                    scheme: token.to_string(),
                    params: Vec::new(),
                });
            } else {
                i += 1;
            }
            continue;
        }

        let mut j = skip_ws(b, j + 1);
        let value = if j < b.len() && b[j] == b'"' {
            j += 1;
            let mut value = String::new();
            let mut closed = false;
            let mut seg = j;
            while j < b.len() {
                match b[j] {
                    b'\\' if j + 1 < b.len() => {
                        value.push_str(&header[seg..j]);
                        let c = header[j + 1..].chars().next().unwrap_or_default();
                        value.push(c);
                        j += 1 + c.len_utf8();
                        seg = j;
                    }
                    b'"' => {
                        value.push_str(&header[seg..j]);
                        j += 1;
                        closed = true;
                        break;
                    }
                    _ => j += 1,
                }
            }
            if !closed {
                debug!("Unterminated quoted string in WWW-Authenticate");
                break;
            }
            value
        } else {
            let vs = j;
            while j < b.len() && b[j] != b',' && !is_ws(b[j]) {
                j += 1;
            }
            header[vs..j].to_string()
        };
        i = j;

        let param = (token.to_ascii_lowercase(), value);
        match out.last_mut() {
            Some(c) => c.params.push(param),
            None => out.push(Challenge {
                scheme: String::new(),
                params: vec![param],
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn parse(v: &'static str) -> WwwAuthenticate {
        let mut headers = HeaderMap::new();
        headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static(v));
        WwwAuthenticate::parse(&headers)
    }

    fn scope(v: &'static str) -> Option<Vec<String>> {
        parse(v).scope()
    }

    fn strings(v: &[&str]) -> Option<Vec<String>> {
        Some(v.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn test_parse_empty_headers() {
        let auth = WwwAuthenticate::parse(&HeaderMap::new());
        assert_eq!(auth.resource_metadata(), None);
        assert_eq!(auth.scope(), None);
        assert_eq!(auth.error(), None);
    }

    #[test]
    fn test_parse_invalid_utf8() {
        let mut headers = HeaderMap::new();
        headers.insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_bytes(b"Bearer \xFF\xFF").unwrap(),
        );
        let auth = WwwAuthenticate::parse(&headers);
        assert!(auth.challenges.is_empty());
    }

    #[test]
    fn test_parse_missing_parameters() {
        let auth = parse("Bearer some_other_param=\"value\"");
        assert_eq!(auth.resource_metadata(), None);
        assert_eq!(auth.scope(), None);
        assert_eq!(auth.error(), None);
        assert_eq!(auth.param("some_other_param"), Some("value"));
    }

    #[test]
    fn test_parse_quoted() {
        let auth = parse(
            "DPoP resource_metadata=\"http://example.com/.well-known/oauth-protected-resource\", scope=\"mcp:all\"",
        );
        assert_eq!(
            auth.resource_metadata(),
            Some("http://example.com/.well-known/oauth-protected-resource")
        );
        assert_eq!(auth.scope(), strings(&["mcp:all"]));
        assert_eq!(auth.challenges[0].scheme, "DPoP");
    }

    #[test]
    fn test_parse_unquoted() {
        let auth = parse(
            "DPoP resource_metadata=http://example.com/.well-known/oauth-protected-resource, scope=mcp:all",
        );
        assert_eq!(
            auth.resource_metadata(),
            Some("http://example.com/.well-known/oauth-protected-resource")
        );
        assert_eq!(auth.scope(), strings(&["mcp:all"]));
    }

    #[test]
    fn test_parse_full() {
        let auth = parse(
            "Bearer error=\"insufficient_scope\", scope=\"admin\", resource_metadata=\"http://localhost/discovery\"",
        );
        assert_eq!(auth.error(), Some("insufficient_scope"));
        assert_eq!(auth.scope(), strings(&["admin"]));
        assert_eq!(auth.resource_metadata(), Some("http://localhost/discovery"));
    }

    #[test]
    fn test_parse_scopes() {
        assert_eq!(
            scope("Bearer scope=\"read write admin\""),
            strings(&["read", "write", "admin"])
        );
        assert_eq!(
            scope("Bearer scope=\"read   write\""),
            strings(&["read", "write"])
        );
        assert_eq!(scope("Bearer scope=\"\""), strings(&[]));
    }

    #[test]
    fn test_parse_unquoted_error() {
        let auth = parse("Bearer error=invalid_token, scope=mcp:all");
        assert_eq!(auth.error(), Some("invalid_token"));
        assert_eq!(auth.scope(), strings(&["mcp:all"]));
    }

    #[test]
    fn test_parse_unclosed_quote() {
        assert_eq!(scope("Bearer scope=\"mcp:all"), None);
    }

    #[test]
    fn test_parse_does_not_match_substrings() {
        // `myscope` must not be mistaken for `scope`.
        assert_eq!(scope("Bearer myscope=\"admin\""), None);
        // `error_description` must not be mistaken for `error`.
        let auth = parse("Bearer error_description=\"error=bad\", error=\"invalid_token\"");
        assert_eq!(auth.error(), Some("invalid_token"));
        // A parameter name inside a quoted value is not a parameter.
        let auth = parse("Bearer realm=\"scope=admin\"");
        assert_eq!(auth.scope(), None);
    }

    #[test]
    fn test_parse_escapes_and_commas_in_quotes() {
        let auth = parse(r#"Bearer realm="a \"quoted\" \\ value", scope="a,b,c", error="err""#);
        assert_eq!(auth.param("realm"), Some(r#"a "quoted" \ value"#));
        assert_eq!(auth.param("scope"), Some("a,b,c"));
        assert_eq!(auth.error(), Some("err"));
    }

    #[test]
    fn test_parse_unquoted_value_stops_at_comma() {
        let auth = parse("Bearer scope=a,b,c, error=err");
        assert_eq!(auth.param("scope"), Some("a"));
    }

    #[test]
    fn test_parse_param_names_case_insensitive() {
        let auth = parse("Bearer Error=\"invalid_token\"");
        assert_eq!(auth.error(), Some("invalid_token"));
    }

    #[test]
    fn test_parse_multiple_challenges() {
        let auth = parse("Bearer realm=\"mcp\", DPoP error=\"use_dpop_nonce\", algs=\"ES256\"");
        assert_eq!(auth.challenges.len(), 2);
        assert_eq!(auth.challenges[0].scheme, "Bearer");
        assert_eq!(auth.challenges[0].param("realm"), Some("mcp"));
        assert_eq!(auth.challenges[1].scheme, "DPoP");
        assert_eq!(auth.challenges[1].param("error"), Some("use_dpop_nonce"));
        assert_eq!(auth.challenges[1].param("algs"), Some("ES256"));
    }

    #[test]
    fn test_parse_multiple_header_lines() {
        let mut headers = HeaderMap::new();
        headers.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"a\""),
        );
        headers.append(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("DPoP resource_metadata=\"http://x/meta\""),
        );
        let auth = WwwAuthenticate::parse(&headers);
        assert_eq!(auth.challenges.len(), 2);
        assert_eq!(auth.resource_metadata(), Some("http://x/meta"));
    }

    #[test]
    fn test_parse_scheme_only_and_whitespace_around_equals() {
        assert_eq!(parse("Bearer").challenges[0].scheme, "Bearer");
        assert_eq!(parse("Bearer scope = \"x\"").param("scope"), Some("x"));
    }
}
