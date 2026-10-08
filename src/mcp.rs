//! # MCP protocol eras and Streamable HTTP request metadata
//!
//! mcp-passport forwards whatever the stdio client speaks:
//!
//! - **Modern** (2026-07-28 and later): every request carries its protocol
//!   version in `_meta`; there is no `initialize`, no session and no GET stream.
//! - **Legacy** (2025-11-25 and earlier): an `initialize` handshake negotiates
//!   the version, which then goes in the `MCP-Protocol-Version` header.
//!
//! For HTTP, modern requests also mirror body fields into headers
//! (`Mcp-Method`, `Mcp-Name`) so that intermediaries can route on them.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

/// `_meta` key carrying the protocol version of a modern request.
pub(crate) const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// Which generation of the protocol a message belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Era {
    /// Per-request metadata (2026-07-28 and later).
    Modern,
    /// `initialize`-based sessions (2025-11-25 and earlier).
    Legacy,
}

/// The protocol version declared in a modern request's `_meta`.
pub(crate) fn meta_protocol_version(payload: &Value) -> Option<&str> {
    payload
        .get("params")?
        .get("_meta")?
        .get(META_PROTOCOL_VERSION)?
        .as_str()
}

pub(crate) fn era_of(payload: &Value) -> Era {
    if meta_protocol_version(payload).is_some() {
        Era::Modern
    } else {
        Era::Legacy
    }
}

pub(crate) fn method_of(payload: &Value) -> Option<&str> {
    payload.get("method")?.as_str()
}

/// Whether `value` can go in an HTTP header as is: visible ASCII, space or tab,
/// no leading/trailing whitespace, and not mistakable for an encoded value.
fn is_plain_header_safe(value: &str) -> bool {
    let bytes = value.as_bytes();
    let printable = bytes
        .iter()
        .all(|&b| b == b'\t' || (0x20..=0x7e).contains(&b));
    let trimmed =
        !matches!(bytes.first(), Some(b' ' | b'\t')) && !matches!(bytes.last(), Some(b' ' | b'\t'));
    let sentinel = value.starts_with("=?base64?") && value.ends_with("?=");
    printable && trimmed && !sentinel
}

/// Encodes a value for an `Mcp-Name` / `Mcp-Param-*` header, using the
/// `=?base64?…?=` form when it can't be sent as plain ASCII.
pub(crate) fn encode_header_value(value: &str) -> String {
    if is_plain_header_safe(value) {
        value.to_string()
    } else {
        format!("=?base64?{}?=", STANDARD.encode(value.as_bytes()))
    }
}

/// The standard request headers of a POST: `Mcp-Method` always, and
/// `Mcp-Name` for `tools/call`, `prompts/get` and `resources/read`.
pub(crate) fn standard_headers(payload: &Value) -> Vec<(&'static str, String)> {
    let mut headers = Vec::new();
    let Some(method) = method_of(payload) else {
        return headers;
    };
    headers.push(("Mcp-Method", encode_header_value(method)));

    let name_field = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    if let Some(name) = name_field
        .and_then(|f| payload.get("params")?.get(f))
        .and_then(Value::as_str)
    {
        headers.push(("Mcp-Name", encode_header_value(name)));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_era_detection() {
        let modern = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": {"_meta": {META_PROTOCOL_VERSION: "2026-07-28"}}});
        assert_eq!(era_of(&modern), Era::Modern);
        assert_eq!(meta_protocol_version(&modern), Some("2026-07-28"));

        let legacy = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"}});
        assert_eq!(era_of(&legacy), Era::Legacy);
        assert_eq!(
            era_of(&json!({"jsonrpc": "2.0", "method": "x"})),
            Era::Legacy
        );
    }

    #[test]
    fn test_encode_header_value_spec_examples() {
        // The examples table of the Streamable HTTP "Value Encoding" section.
        assert_eq!(encode_header_value("us-west1"), "us-west1");
        assert_eq!(
            encode_header_value("Hello, 世界"),
            "=?base64?SGVsbG8sIOS4lueVjA==?="
        );
        assert_eq!(encode_header_value(" padded "), "=?base64?IHBhZGRlZCA=?=");
        assert_eq!(
            encode_header_value("line1\nline2"),
            "=?base64?bGluZTEKbGluZTI=?="
        );
        assert_eq!(
            encode_header_value("=?base64?literal?="),
            "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="
        );
    }

    #[test]
    fn test_encode_header_value_edges() {
        assert_eq!(encode_header_value("a b\tc"), "a b\tc");
        assert_eq!(encode_header_value("trailing\t"), "=?base64?dHJhaWxpbmcJ?=");
        assert_eq!(encode_header_value("del\x7f"), "=?base64?ZGVsfw==?=");
        assert_eq!(
            encode_header_value("=?base64?no-suffix"),
            "=?base64?no-suffix"
        );
    }

    #[test]
    fn test_standard_headers() {
        let call = json!({"method": "tools/call", "params": {"name": "get_weather"}});
        assert_eq!(
            standard_headers(&call),
            vec![
                ("Mcp-Method", "tools/call".to_string()),
                ("Mcp-Name", "get_weather".to_string())
            ]
        );
        let read = json!({"method": "resources/read", "params": {"uri": "file:///ü.txt"}});
        assert_eq!(
            standard_headers(&read)[1],
            ("Mcp-Name", "=?base64?ZmlsZTovLy/DvC50eHQ=?=".to_string())
        );
        let prompt = json!({"method": "prompts/get", "params": {"name": "summary"}});
        assert_eq!(standard_headers(&prompt)[1].1, "summary");
        let list = json!({"method": "tools/list"});
        assert_eq!(
            standard_headers(&list),
            vec![("Mcp-Method", "tools/list".to_string())]
        );
        assert!(standard_headers(&json!({"id": 1, "result": {}})).is_empty());
    }
}
