//! End to end against Keycloak 26.8.0 and a strict MCP 2026-07-28 resource
//! server that validates DPoP-bound tokens through Keycloak introspection.
//!
//! Covers: RFC 9728 → RFC 8414/OIDC discovery, PKCE check, PAR with dpop_jkt,
//! browser login, RFC 9207 `iss` check, DPoP token exchange, 2026-07-28 headers
//! and x-mcp-header, step-up with scope union, refresh with Keycloak's refresh
//! tokens, and subscriptions/listen with cancellation.
//!
//! Needs Docker: `cargo test --test keycloak_2026_e2e_test -- --ignored`.

mod common;

use common::mcp_server::{self, Introspection, ServerOptions, MODERN};
use common::modern;
use fantoccini::{Client, ClientBuilder, Locator};
use mcp_passport::auth::{OidcConfig, Timeouts};
use mcp_passport::config::AuthScheme;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::info;

type UrlSlot = Arc<Mutex<Option<oneshot::Sender<String>>>>;

/// Runs `call` while completing the browser login it triggers.
async fn with_login<F, T>(browser: &Client, slot: &UrlSlot, call: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let (tx, rx) = oneshot::channel();
    *slot.lock().await = Some(tx);
    let login = async {
        let url = tokio::time::timeout(Duration::from_secs(60), rx)
            .await
            .expect("an authorization URL")
            .expect("URL sender kept");
        info!("Logging in at {url}");
        assert!(url.contains("request_uri="), "PAR request_uri in {url}");
        browser.goto(&url).await.unwrap();
        // First login shows the form; later ones may reuse the SSO session.
        let target = match browser
            .wait()
            .at_most(Duration::from_secs(30))
            .for_element(Locator::XPath(
                "//input[@id='username'] | //h1[contains(., 'Authentication Successful')]",
            ))
            .await
        {
            Ok(t) => t,
            Err(e) => {
                let current = browser.current_url().await.map(|u| u.to_string());
                let source = browser.source().await.unwrap_or_default();
                panic!("login page not reached ({e}); at {current:?}: {source}");
            }
        };
        if target.tag_name().await.unwrap() == "input" {
            browser
                .find(Locator::Id("username"))
                .await
                .unwrap()
                .send_keys("jdoe")
                .await
                .unwrap();
            browser
                .find(Locator::Id("password"))
                .await
                .unwrap()
                .send_keys("password")
                .await
                .unwrap();
            browser
                .find(Locator::Id("kc-login"))
                .await
                .unwrap()
                .click()
                .await
                .unwrap();
        }
        browser
            .wait()
            .at_most(Duration::from_secs(30))
            .for_element(Locator::XPath(
                "//h1[contains(., 'Authentication Successful')]",
            ))
            .await
            .expect("the success page after the callback");
    };
    let (result, ()) = tokio::join!(call, login);
    result
}

#[tokio::test]
#[ignore]
async fn test_keycloak_26_8_with_mcp_2026_07_28() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,mcp_passport=debug")
        .with_writer(std::io::stderr)
        .try_init();

    let kc = common::start_keycloak().await?;
    common::add_optional_scopes(&kc, "mcp-passport", &["mcp:tools", "mcp:admin"]).await?;
    let _chrome = common::start_chrome().await?;

    let server = mcp_server::start(ServerOptions {
        issuer: Some(kc.realm()),
        introspection: Some(Introspection {
            url: kc.oidc_endpoint("token/introspect"),
            client_id: "mock-mcp".into(),
            client_secret: "mock-mcp-secret".into(),
        }),
        reject_valid_tokens: 0,
    })
    .await;

    let slot: UrlSlot = Arc::default();
    let vault = Vault::in_memory("keycloak-2026-e2e");
    let proxy = Proxy::new(
        &server.url(),
        "jdoe",
        OidcConfig {
            client_id: "mcp-passport".into(),
            redirect_url: "http://127.0.0.1:8082/callback".into(),
            internal_url_tx: slot.clone(),
            timeouts: Timeouts {
                auth: Duration::from_secs(90),
                ..Default::default()
            },
            ..Default::default()
        },
        vault.clone(),
        MODERN,
        AuthScheme::Bearer,
    );

    let mut caps = serde_json::map::Map::new();
    caps.insert(
        "goog:chromeOptions".into(),
        json!({"args": ["--headless", "--disable-gpu", "--no-sandbox"]}),
    );
    let browser = ClientBuilder::native()
        .capabilities(caps)
        .connect(common::CHROME_URL)
        .await?;

    // 1. First request: 401 → discovery from the resource metadata → login.
    let discover = with_login(
        &browser,
        &slot,
        proxy.call(modern(1, "server/discover", json!({}))),
    )
    .await;
    let discover = match discover {
        Ok(v) => v.expect("a server/discover result"),
        Err(e) => {
            let logs = kc.container.stdout_to_vec().await.unwrap_or_default();
            let logs = String::from_utf8_lossy(&logs);
            let tail: Vec<&str> = logs.lines().rev().take(60).collect();
            for line in tail.into_iter().rev() {
                eprintln!("KC| {line}");
            }
            panic!("{e:#}; server rejections: {:?}", server.rejections());
        }
    };
    assert_eq!(discover["result"]["supportedVersions"][0], MODERN);
    let meta = vault.get_meta("jdoe")?.expect("credential metadata");
    assert_eq!(meta.issuer.as_deref(), Some(kc.realm().as_str()));
    assert!(
        meta.scopes.contains(&"mcp:tools".to_string()),
        "credential metadata lacks mcp:tools"
    );
    assert!(
        vault.get_refresh_token("jdoe")?.is_some(),
        "Keycloak issued a refresh token"
    );

    // 2. tools/list (invalid tool filtered) and tools/call with Mcp-Param-Region.
    let list = proxy
        .call(modern(2, "tools/list", json!({})))
        .await?
        .unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["sql", "admin_tool", "slow"]);
    let call = proxy
        .call(modern(
            3,
            "tools/call",
            json!({"name": "sql",
            "arguments": {"region": "eu-west1", "query": "SELECT 1"}}),
        ))
        .await?
        .unwrap();
    assert_eq!(call["result"]["content"][0]["text"], "region=eu-west1");

    // 3. Step-up: 403 insufficient_scope → login for mcp:admin, keeping mcp:tools.
    let admin = with_login(
        &browser,
        &slot,
        proxy.call(modern(
            4,
            "tools/call",
            json!({"name": "admin_tool", "arguments": {}}),
        )),
    )
    .await?
    .unwrap();
    assert_eq!(admin["result"]["content"][0]["text"], "admin ok");
    let scopes = vault.get_meta("jdoe")?.unwrap().scopes;
    assert!(
        scopes.contains(&"mcp:tools".to_string()) && scopes.contains(&"mcp:admin".to_string()),
        "step-up must keep mcp:tools and add mcp:admin"
    );

    // 4. A rejected token is renewed with Keycloak's refresh token, silently.
    let refresh_before = vault.get_refresh_token("jdoe")?;
    let token_before = vault.get_token("jdoe")?;
    server.reject_next(1);
    let again = proxy
        .call(modern(
            5,
            "tools/call",
            json!({"name": "sql",
            "arguments": {"region": "us-east1", "query": "SELECT 2"}}),
        ))
        .await?
        .unwrap();
    assert_eq!(again["result"]["content"][0]["text"], "region=us-east1");
    // `assert!`, not `assert_ne!`: a failure must not print the tokens.
    assert!(
        vault.get_token("jdoe")? != token_before,
        "a new access token"
    );
    assert!(
        vault.get_refresh_token("jdoe")? != refresh_before,
        "a rotated refresh token"
    );
    assert!(slot.lock().await.is_none(), "no browser login was needed");

    // 5. subscriptions/listen with the token, then cancellation (closing the stream).
    let (tx, mut rx) = mpsc::channel(8);
    let p = proxy.clone();
    let listen = tokio::spawn(async move {
        p.handle_request(
            modern(
                "sub-1",
                "subscriptions/listen",
                json!({"notifications": {"toolsListChanged": true}}),
            ),
            &tx,
        )
        .await
    });
    let ack: Value = serde_json::from_str(
        &tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await?
            .unwrap(),
    )?;
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
    listen.abort();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !server.streams_closed().contains(&json!("sub-1"))
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(server.streams_closed().contains(&json!("sub-1")));

    // Every rejection was an expected one: never a bad DPoP proof.
    let rejections = server.rejections();
    info!("Server rejections: {rejections:?}");
    assert!(
        rejections.iter().all(|r| r == "no access token"
            || r == "insufficient scope"
            || r == "forced rejection"),
        "unexpected rejections: {rejections:?}"
    );
    assert_eq!(
        rejections
            .iter()
            .filter(|r| *r == "forced rejection")
            .count(),
        1
    );

    browser.close().await?;
    Ok(())
}
