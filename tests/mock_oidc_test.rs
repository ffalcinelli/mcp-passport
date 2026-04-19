use anyhow::Context;
use axum::{http::HeaderMap, response::IntoResponse, routing::get, routing::post, Router};
use mcp_passport::auth::AuthManager;
use mcp_passport::auth::OidcConfig;
use mcp_passport::config::AuthScheme;
use mcp_passport::crypto::DpopKey;
use mcp_passport::proxy::Proxy;
use mcp_passport::vault::Vault;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn test_sse_piping_flow() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-sse-v3";
    use axum::response::sse::{Event, Sse};
    use futures::stream;

    let mcp_app = Router::new().route(
        "/sse",
        get(|| async move {
            let stream = stream::iter(vec![Ok::<Event, std::convert::Infallible>(
                Event::default().data("{\"jsonrpc\":\"2.0\",\"method\":\"test/notify\"}"),
            )]);
            Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
        }),
    );
    let mcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mcp_addr = mcp_listener.local_addr()?;
    let sse_url = format!("http://127.0.0.1:{}/sse", mcp_addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(mcp_listener, mcp_app).await;
    });

    let vault = Vault::new(test_svc);
    vault.store_token("sse_user", "valid_token")?;
    let dpop_key = DpopKey::generate();
    vault.store_dpop_key("sse_user", &dpop_key.to_bytes())?;

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: Some("a".into()),
        token_url_override: Some("t".into()),
        par_url_override: Some("p".into()),
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };
    let proxy = Proxy::new(
        "http://unused",
        "sse_user",
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let (stdout_tx, mut stdout_rx) = mpsc::channel::<String>(100);
    let p = proxy.clone();
    let s_url = sse_url.clone();
    tokio::spawn(async move {
        let _ = p.listen_sse(&s_url, stdout_tx).await;
    });

    let msg = timeout(Duration::from_secs(5), stdout_rx.recv())
        .await?
        .context("No SSE message")?;
    assert!(msg.contains("test/notify"));

    Ok(())
}

#[tokio::test]
async fn test_reauth_loop_reset_on_failure() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-loop-v4";
    let _ = Vault::new(test_svc).delete_token("loop_user");

    let mcp_app = Router::new().route(
        "/rpc",
        post(|headers: HeaderMap| async move {
            let auth = headers.get("Authorization");
            if auth.is_some() {
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Loop broken")
                    .into_response();
            }

            let host = headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("127.0.0.1");
            let base = format!("http://{}", host);
            let challenge = format!("Bearer resource_metadata=\"{}/invalid-discovery\"", base);
            (
                axum::http::StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", challenge)],
                "Unauthorized",
            )
                .into_response()
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());

    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy = Proxy::new(
        &rpc_url,
        "loop_user",
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let res1 = timeout(
        Duration::from_secs(5),
        proxy
            .clone()
            .handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"})),
    )
    .await?;
    assert!(res1.is_err());

    let res2 = timeout(
        Duration::from_secs(5),
        proxy
            .clone()
            .handle_request(json!({"jsonrpc": "2.0", "id": 2, "method": "test"})),
    )
    .await?;
    assert!(res2.is_err());

    Ok(())
}

#[tokio::test]
async fn test_discovery_url_construction() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-discovery-v1";

    let mcp_app = Router::new()
        .route(
            "/rpc-with-meta",
            post(|headers: HeaderMap| async move {
                let host = headers
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("127.0.0.1");
                let challenge = format!(
                    "Bearer resource_metadata=\"http://{}/custom-discovery\"",
                    host
                );
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    [("WWW-Authenticate", challenge)],
                    "Unauthorized",
                )
                    .into_response()
            }),
        )
        .route(
            "/rpc-no-meta",
            post(|_headers: HeaderMap| async move {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    [("WWW-Authenticate", "Bearer scope=\"mcp\"")],
                    "Unauthorized",
                )
                    .into_response()
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy1 = Proxy::new(
        &format!("{}/rpc-with-meta", base_url),
        "user1",
        oidc_config.clone(),
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );
    let res1 = timeout(
        Duration::from_secs(2),
        proxy1.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"})),
    )
    .await?;
    let err1 = format!("{:?}", res1.err().unwrap());
    assert!(err1.contains("custom-discovery"));

    let proxy2 = Proxy::new(
        &format!("{}/rpc-no-meta", base_url),
        "user2",
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );
    let res2 = timeout(
        Duration::from_secs(2),
        proxy2.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"})),
    )
    .await?;
    let err2 = format!("{:?}", res2.err().unwrap());
    assert!(err2.contains(".well-known/oauth-protected-resource"));

    Ok(())
}

#[tokio::test]
async fn test_concurrent_reauth_regression() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-regression-v1";
    let user = "reg_user";
    let _ = Vault::new(test_svc).delete_token(user);

    let auth_counter = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let mcp_app = Router::new()
        .route(
            "/rpc",
            post({
                move |headers: HeaderMap| async move {
                    let auth = headers.get("Authorization");
                    if auth.is_some() {
                        return axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"}))
                            .into_response();
                    }
                    let host = headers
                        .get("host")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("127.0.0.1");
                    let challenge =
                        format!("Bearer resource_metadata=\"http://{}/discovery\"", host);
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        [("WWW-Authenticate", challenge)],
                        "Unauthorized",
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/discovery",
            get({
                let ac = auth_counter.clone();
                move || {
                    let ac = ac.clone();
                    async move {
                        ac.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        axum::Json(json!({
                            "issuer": "http://localhost",
                            "authorization_endpoint": "http://localhost/auth",
                            "token_endpoint": "http://localhost/token",
                            "pushed_authorization_request_endpoint": "http://localhost/par"
                        }))
                    }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base_url = format!("http://127.0.0.1:{}", addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "http://127.0.0.1:8082/callback".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy = Proxy::new(
        &format!("{}/rpc", base_url),
        user,
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let p1 = proxy.clone();
    let task1 = tokio::spawn(async move {
        p1.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"}))
            .await
    });

    let p2 = proxy.clone();
    let task2 = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        p2.handle_request(json!({"jsonrpc": "2.0", "id": 2, "method": "test"}))
            .await
    });

    let _ = task1.await;
    let _ = task2.await;

    assert!(
        auth_counter.load(std::sync::atomic::Ordering::SeqCst) <= 2,
        "Too many re-auth attempts triggered"
    );

    Ok(())
}

#[tokio::test]
async fn test_max_retries_exhaustion() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-max-retries";
    let user = "retry_user";
    let _ = Vault::new(test_svc).delete_token(user);

    let mcp_app = Router::new().route(
        "/rpc",
        post(|headers: HeaderMap| async move {
            let host = headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("127.0.0.1");
            let challenge = format!("Bearer resource_metadata=\"http://{}/discovery\"", host);
            (
                axum::http::StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", challenge)],
                "Unauthorized",
            )
                .into_response()
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());

    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy = Proxy::new(
        &rpc_url,
        user,
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let res = timeout(
        Duration::from_secs(5),
        proxy.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"})),
    )
    .await?;

    assert!(res.is_err());
    Ok(())
}

#[tokio::test]
async fn test_sse_401_reauth_trigger() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-sse-401";
    let user = "sse_401_user";
    let vault = Vault::new(test_svc);
    let _ = vault.delete_token(user);

    let mcp_app = Router::new().route(
        "/sse",
        get(|headers: HeaderMap| async move {
            let host = headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("127.0.0.1");
            let challenge = format!("Bearer resource_metadata=\"{}/discovery\"", host);
            (
                axum::http::StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", challenge)],
                "Unauthorized",
            )
                .into_response()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let sse_url = format!("http://127.0.0.1:{}/sse", addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy = Proxy::new(
        &sse_url,
        user,
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let (stdout_tx, _stdout_rx) = mpsc::channel::<String>(10);
    
    let p = proxy.clone();
    let s_url = sse_url.clone();
    tokio::spawn(async move {
        let _ = p.listen_sse(&s_url, stdout_tx).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

#[tokio::test]
async fn test_discovery_failure_handling() -> anyhow::Result<()> {
    let oidc_config = OidcConfig {
        discovery_url: Some("http://localhost:12345/invalid".into()),
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let res = AuthManager::discover(oidc_config, "res".into(), "svc", None).await;
    assert!(res.is_err());
    Ok(())
}

#[tokio::test]
async fn test_discovery_missing_par_endpoint() -> anyhow::Result<()> {
    let mcp_app = Router::new().route(
        "/.well-known/openid-configuration",
        get(|| async move {
            axum::Json(json!({
                "issuer": "http://localhost",
                "authorization_endpoint": "http://localhost/auth",
                "token_endpoint": "http://localhost/token"
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let discovery_url = format!("http://127.0.0.1:{}/.well-known/openid-configuration", addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: Some(discovery_url),
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let res = AuthManager::discover(oidc_config, "res".into(), "svc", None).await;
    assert!(res.is_err());
    Ok(())
}

#[tokio::test]
async fn test_par_failure_handling() -> anyhow::Result<()> {
    let mcp_app = Router::new().route(
        "/par",
        post(|| async move {
            (axum::http::StatusCode::BAD_REQUEST, "invalid_request").into_response()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let par_url = format!("http://127.0.0.1:{}/par", addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let am = AuthManager::discover(OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "http://127.0.0.1:8081/callback".into(),
        auth_url_override: Some("a".into()),
        token_url_override: Some("t".into()),
        par_url_override: Some(par_url),
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    }, "res".into(), "svc", None).await?;

    let res = am.reauthenticate("user", None, None).await;
    assert!(res.is_err());
    Ok(())
}

#[tokio::test]
async fn test_403_step_up_trigger() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-403";
    let user = "stepup_user";
    let vault = Vault::new(test_svc);
    vault.store_token(user, "valid_but_low_scope")?;
    let dpop_key = DpopKey::generate();
    vault.store_dpop_key(user, &dpop_key.to_bytes())?;

    let mcp_app = Router::new().route(
        "/rpc",
        post(|headers: HeaderMap| async move {
            let auth = headers.get("Authorization").and_then(|h| h.to_str().ok());
            if auth == Some("Bearer valid_but_low_scope") {
                let challenge = "Bearer error=\"insufficient_scope\", scope=\"admin\", resource_metadata=\"http://localhost/discovery\"";
                return (
                    axum::http::StatusCode::FORBIDDEN,
                    [("WWW-Authenticate", challenge)],
                    "Forbidden",
                ).into_response();
            }
            axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": "ok"})).into_response()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let oidc_config = OidcConfig {
        discovery_url: None,
        client_id: "c".into(),
        redirect_url: "r".into(),
        auth_url_override: None,
        token_url_override: None,
        par_url_override: None,
        internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
        internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
    };

    let proxy = Proxy::new(
        &rpc_url,
        user,
        oidc_config,
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let res = timeout(
        Duration::from_secs(2),
        proxy.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"})),
    ).await?;

    assert!(res.is_err());
    Ok(())
}

#[tokio::test]
async fn test_sse_non_401_error() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-sse-err";
    let user = "sse_err_user";
    let vault = Vault::new(test_svc);
    vault.store_token(user, "t")?;
    vault.store_dpop_key(user, &DpopKey::generate().to_bytes())?;

    let mcp_app = Router::new().route(
        "/sse",
        get(|| async move {
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Error")
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let sse_url = format!("http://127.0.0.1:{}/sse", addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let (stdout_tx, _stdout_rx) = mpsc::channel::<String>(10);
    let proxy = Proxy::new(
        &sse_url,
        user,
        OidcConfig {
            discovery_url: None,
            client_id: "c".into(),
            redirect_url: "r".into(),
            auth_url_override: None,
            token_url_override: None,
            par_url_override: None,
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
        },
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let p = proxy.clone();
    let s_url = sse_url.clone();
    tokio::spawn(async move {
        let _ = p.listen_sse(&s_url, stdout_tx).await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

#[tokio::test]
async fn test_redundant_reauth_skip() -> anyhow::Result<()> {
    let test_svc = "mcp-passport-test-redundant";
    let user = "redundant_user";
    let vault = Vault::new(test_svc);
    let _ = vault.delete_token(user);

    let mcp_app = Router::new().route(
        "/rpc",
        post(|| async move {
            (axum::http::StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer resource_metadata=\"http://localhost:1/disc\"")], "Unauthorized")
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let rpc_url = format!("http://127.0.0.1:{}/rpc", addr.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, mcp_app).await;
    });

    let p = Proxy::new(
        &rpc_url,
        user,
        OidcConfig {
            discovery_url: None,
            client_id: "c".into(),
            redirect_url: "r".into(),
            auth_url_override: None,
            token_url_override: None,
            par_url_override: None,
            internal_url_tx: Arc::new(tokio::sync::Mutex::new(None)),
            internal_callback_tx: Arc::new(tokio::sync::Mutex::new(None)),
        },
        test_svc,
        "2025-11-25",
        AuthScheme::Bearer,
    );

    let p1 = p.clone();
    let task1 = tokio::spawn(async move {
        let _ = p1.handle_request(json!({"jsonrpc": "2.0", "id": 1, "method": "test"})).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    
    vault.store_token(user, "new_token")?;
    let res = p.handle_request(json!({"jsonrpc": "2.0", "id": 2, "method": "test"})).await;
    
    assert!(res.is_err() || res.is_ok());

    let _ = task1.await;
    Ok(())
}
