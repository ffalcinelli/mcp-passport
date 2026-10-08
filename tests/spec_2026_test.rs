//! MCP 2026-07-28 conformance through the real stdio path, against a strict
//! dual-era server (no auth, no Docker).

mod common;

use common::mcp_server::{self, ServerOptions, LEGACY, MODERN};
use common::{config, modern, StdioClient};
use mcp_passport::vault::Vault;
use serde_json::{json, Value};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(5);

async fn client() -> (mcp_server::McpServer, StdioClient) {
    let server = mcp_server::start(ServerOptions::default()).await;
    let client = StdioClient::start(
        config(&[
            "--remote-mcp-url",
            &server.url(),
            "--oidc-redirect-url",
            "http://127.0.0.1:1/callback",
        ]),
        Vault::in_memory("spec-2026"),
    );
    (server, client)
}

fn tool_names(list: &Value) -> Vec<String> {
    list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn test_modern_discover_list_and_call() {
    let (server, mut client) = client().await;

    let discover = client
        .call(modern(1, "server/discover", json!({})), WAIT)
        .await;
    assert_eq!(discover["result"]["supportedVersions"][0], MODERN);
    assert_eq!(discover["result"]["resultType"], "complete");

    // The tool with an invalid x-mcp-header annotation is filtered out.
    let list = client.call(modern(2, "tools/list", json!({})), WAIT).await;
    assert_eq!(tool_names(&list), vec!["sql", "admin_tool", "slow"]);

    // Mcp-Name and Mcp-Param-Region are mirrored (the server checks them).
    let call = client
        .call(
            modern(
                3,
                "tools/call",
                json!({"name": "sql",
                "arguments": {"region": "eu-west1", "query": "SELECT 1"}}),
            ),
            WAIT,
        )
        .await;
    assert_eq!(call["result"]["content"][0]["text"], "region=eu-west1");

    // Non-ASCII values travel base64-encoded and are decoded by the server.
    let call = client
        .call(
            modern(
                4,
                "tools/call",
                json!({"name": "sql",
                "arguments": {"region": "Zürich", "query": "SELECT 1"}}),
            ),
            WAIT,
        )
        .await;
    assert_eq!(call["result"]["content"][0]["text"], "region=Zürich");

    let posted = server.posted("tools/call");
    assert_eq!(
        posted[1].headers["mcp-param-region"],
        "=?base64?WsO8cmljaA==?="
    );
    assert!(server.rejections().is_empty());
    client.close().await.unwrap();

    // No session ids and no GET stream in the modern era.
    assert_eq!(server.gets(), 0);
    let log = server.log.lock().unwrap();
    assert!(log
        .requests
        .iter()
        .all(|r| !r.headers.contains_key("mcp-session-id")));
}

#[tokio::test]
async fn test_unsupported_version_error_is_passed_through() {
    let (_server, mut client) = client().await;
    let mut request = modern(1, "tools/list", json!({}));
    request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    let response = client.call(request, WAIT).await;
    assert_eq!(response["error"]["code"], -32022);
    assert_eq!(response["error"]["data"]["supported"][0], MODERN);
    client.close().await.unwrap();
}

#[tokio::test]
async fn test_unknown_method_is_a_jsonrpc_error() {
    let (_server, mut client) = client().await;
    let response = client
        .call(modern(1, "nope/nothing", json!({})), WAIT)
        .await;
    assert_eq!(response["error"]["code"], -32601);
    client.close().await.unwrap();
}

#[tokio::test]
async fn test_cancellation_closes_the_response_stream() {
    let (server, mut client) = client().await;
    client
        .send(modern(
            "slow-1",
            "tools/call",
            json!({"name": "slow", "arguments": {}}),
        ))
        .await;
    // Progress arrives while the call runs.
    let progress = client.recv(WAIT).await.unwrap();
    assert_eq!(progress["method"], "notifications/progress");

    client
        .send(
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": "slow-1", "reason": "user"}}),
        )
        .await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while server.streams_closed().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(server.streams_closed(), vec![json!("slow-1")]);
    // Nothing is POSTed for the cancellation on Streamable HTTP.
    assert!(server.posted("notifications/cancelled").is_empty());

    // The proxy never answers the cancelled request.
    while let Some(msg) = client.recv(Duration::from_millis(200)).await {
        assert!(msg.get("id").is_none(), "unexpected response {msg}");
    }
    client.close().await.unwrap();
}

#[tokio::test]
async fn test_subscriptions_listen() {
    let (server, mut client) = client().await;
    client
        .send(modern(
            "sub-1",
            "subscriptions/listen",
            json!({"notifications": {"toolsListChanged": true}}),
        ))
        .await;
    let ack = client.recv(WAIT).await.unwrap();
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
    assert_eq!(
        ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        "sub-1"
    );
    assert_eq!(ack["params"]["notifications"]["toolsListChanged"], true);
    let changed = client.recv(WAIT).await.unwrap();
    assert_eq!(changed["method"], "notifications/tools/list_changed");

    // The stream stays open until the client cancels the subscription.
    client
        .send(
            json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": "sub-1"}}),
        )
        .await;
    let deadline = tokio::time::Instant::now() + WAIT;
    while server.streams_closed().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(server.streams_closed(), vec![json!("sub-1")]);
    client.close().await.unwrap();
}

#[tokio::test]
async fn test_stdin_close_ends_open_streams() {
    let (server, mut client) = client().await;
    client
        .send(modern(
            "sub-1",
            "subscriptions/listen",
            json!({"notifications": {"toolsListChanged": true}}),
        ))
        .await;
    client.recv(WAIT).await.unwrap();
    // The proxy exits (after its grace period) although the stream is open.
    client.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.streams_closed(), vec![json!("sub-1")]);
}

#[tokio::test]
async fn test_legacy_session_flow() {
    let (server, mut client) = client().await;

    let init = client
        .call(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": LEGACY, "capabilities": {},
                "clientInfo": {"name": "legacy", "version": "1"}}}),
            WAIT,
        )
        .await;
    assert_eq!(init["result"]["protocolVersion"], LEGACY);
    client
        .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;

    client
        .send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .await;
    let (list, mut pushed) = client.response(2, WAIT).await;
    assert_eq!(tool_names(&list), vec!["sql", "admin_tool", "slow"]);

    // Legacy servers push on the standalone GET stream, with the session. The
    // push may arrive before or after the tools/list response.
    if pushed.is_empty() {
        pushed.push(
            client
                .recv(WAIT)
                .await
                .expect("a message on the GET stream"),
        );
    }
    assert_eq!(pushed[0]["params"]["data"], "legacy stream");
    assert_eq!(server.gets(), 1);

    let listed = &server.posted("tools/list")[0];
    assert_eq!(listed.headers["mcp-session-id"], "sess-1");
    assert_eq!(listed.headers["mcp-protocol-version"], LEGACY);
    client.close().await.unwrap();
}
