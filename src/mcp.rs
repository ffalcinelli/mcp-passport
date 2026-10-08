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

/// JSON-RPC error code for headers that don't match the body (2026-07-28).
pub(crate) const HEADER_MISMATCH: i64 = -32020;

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

/// The `x-mcp-header` annotations of one tool: property path → header name
/// (the `{name}` of `Mcp-Param-{name}`).
pub(crate) type ToolHeaders = Vec<(Vec<String>, String)>;

/// RFC 9110 `tchar`.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// Whether a schema `type` is a primitive allowed to carry `x-mcp-header`:
/// `string`, `integer` or `boolean` (optionally together with `null`).
fn is_header_type(ty: Option<&Value>) -> bool {
    let allowed = |t: &str| matches!(t, "string" | "integer" | "boolean");
    match ty {
        Some(Value::String(t)) => allowed(t),
        Some(Value::Array(ts)) => {
            let non_null: Vec<&str> = ts
                .iter()
                .filter_map(Value::as_str)
                .filter(|t| *t != "null")
                .collect();
            ts.iter().all(Value::is_string) && non_null.len() == 1 && allowed(non_null[0])
        }
        _ => false,
    }
}

/// Collects `x-mcp-header` annotations of the schema `node` at `path`.
/// `reachable` is true while the path consists only of `properties` keys.
fn collect_headers(
    node: &Value,
    path: &mut Vec<String>,
    reachable: bool,
    out: &mut ToolHeaders,
) -> Result<(), String> {
    match node {
        Value::Object(map) => {
            if let Some(annotation) = map.get("x-mcp-header") {
                let name = annotation.as_str().ok_or("x-mcp-header must be a string")?;
                if name.is_empty() || !name.chars().all(is_tchar) {
                    return Err(format!("x-mcp-header '{name}' is not a valid header name"));
                }
                if !reachable || path.is_empty() {
                    return Err(format!(
                        "x-mcp-header '{name}' is not on a property reachable through `properties` only"
                    ));
                }
                if !is_header_type(map.get("type")) {
                    return Err(format!(
                        "x-mcp-header '{name}' is on a parameter that is not a string, integer or boolean"
                    ));
                }
                if out.iter().any(|(_, n)| n.eq_ignore_ascii_case(name)) {
                    return Err(format!("x-mcp-header '{name}' is not unique"));
                }
                out.push((path.clone(), name.to_string()));
            }
            for (key, value) in map {
                match (key.as_str(), value) {
                    ("x-mcp-header", _) => {}
                    ("properties", Value::Object(props)) => {
                        for (prop, schema) in props {
                            path.push(prop.clone());
                            let res = collect_headers(schema, path, reachable, out);
                            path.pop();
                            res?;
                        }
                    }
                    // Anything else (items, oneOf, $defs, if/then, ...) is not
                    // statically reachable.
                    _ => collect_headers(value, path, false, out)?,
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_headers(item, path, false, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validates the `x-mcp-header` annotations of a tool's `inputSchema` and
/// returns them, or why the tool definition is invalid.
pub(crate) fn tool_header_annotations(input_schema: &Value) -> Result<ToolHeaders, String> {
    let mut out = Vec::new();
    collect_headers(input_schema, &mut Vec::new(), true, &mut out)?;
    Ok(out)
}

/// The `Mcp-Param-*` headers of a `tools/call` request, from the arguments at
/// the annotated paths. Missing and `null` values are omitted.
pub(crate) fn param_headers(
    arguments: Option<&Value>,
    headers: &ToolHeaders,
) -> Vec<(String, String)> {
    let Some(arguments) = arguments else {
        return Vec::new();
    };
    headers
        .iter()
        .filter_map(|(path, name)| {
            let value = path.iter().try_fold(arguments, |v, key| v.get(key))?;
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
                _ => return None,
            };
            Some((format!("Mcp-Param-{name}"), encode_header_value(&text)))
        })
        .collect()
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

    #[test]
    fn test_tool_header_annotations_valid() {
        let schema = json!({
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "query": {"type": "string"},
                "opts": {"type": "object", "properties": {
                    "dry_run": {"type": "boolean", "x-mcp-header": "Dry-Run"},
                    "limit": {"type": ["integer", "null"], "x-mcp-header": "Limit"}
                }}
            }
        });
        let headers = tool_header_annotations(&schema).unwrap();
        assert_eq!(
            headers,
            vec![
                (
                    vec!["opts".to_string(), "dry_run".to_string()],
                    "Dry-Run".to_string()
                ),
                (
                    vec!["opts".to_string(), "limit".to_string()],
                    "Limit".to_string()
                ),
                (vec!["region".to_string()], "Region".to_string()),
            ]
        );
        assert!(tool_header_annotations(&json!({"type": "object"}))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_tool_header_annotations_invalid() {
        let bad = |prop: Value| {
            tool_header_annotations(&json!({"type": "object", "properties": {"p": prop}}))
                .unwrap_err()
        };
        assert!(bad(json!({"type": "string", "x-mcp-header": ""})).contains("valid header"));
        assert!(bad(json!({"type": "string", "x-mcp-header": "Bad Name"})).contains("valid header"));
        assert!(bad(json!({"type": "string", "x-mcp-header": "Bad\r\nX"})).contains("valid header"));
        assert!(bad(json!({"type": "number", "x-mcp-header": "N"})).contains("not a string"));
        assert!(bad(json!({"type": "object", "x-mcp-header": "O"})).contains("not a string"));
        assert!(
            bad(json!({"type": "array", "items": {"type": "string", "x-mcp-header": "I"}}))
                .contains("reachable")
        );
        assert!(
            bad(json!({"oneOf": [{"type": "string", "x-mcp-header": "One"}]}))
                .contains("reachable")
        );
        let dup = json!({"type": "object", "properties": {
            "a": {"type": "string", "x-mcp-header": "Tenant"},
            "b": {"type": "string", "x-mcp-header": "tenant"}
        }});
        assert!(tool_header_annotations(&dup)
            .unwrap_err()
            .contains("unique"));
        let defs =
            json!({"type": "object", "$defs": {"x": {"type": "string", "x-mcp-header": "D"}}});
        assert!(tool_header_annotations(&defs)
            .unwrap_err()
            .contains("reachable"));
    }

    #[test]
    fn test_param_headers() {
        let headers = vec![
            (vec!["region".to_string()], "Region".to_string()),
            (
                vec!["opts".to_string(), "dry_run".to_string()],
                "Dry-Run".to_string(),
            ),
            (vec!["count".to_string()], "Count".to_string()),
            (vec!["missing".to_string()], "Missing".to_string()),
            (vec!["nothing".to_string()], "Nothing".to_string()),
        ];
        let args = json!({
            "region": "Hello, 世界",
            "opts": {"dry_run": true},
            "count": -7,
            "nothing": null
        });
        assert_eq!(
            param_headers(Some(&args), &headers),
            vec![
                (
                    "Mcp-Param-Region".to_string(),
                    "=?base64?SGVsbG8sIOS4lueVjA==?=".to_string()
                ),
                ("Mcp-Param-Dry-Run".to_string(), "true".to_string()),
                ("Mcp-Param-Count".to_string(), "-7".to_string()),
            ]
        );
        assert!(param_headers(None, &headers).is_empty());
    }
}
