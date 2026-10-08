//! Helpers shared by the Docker-based integration tests.
#![allow(dead_code)]

use testcontainers::{
    core::Mount, core::WaitFor, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt,
};

/// Keycloak version the end-to-end suites run against.
pub const KEYCLOAK_IMAGE: (&str, &str) = ("quay.io/keycloak/keycloak", "26.8.0");

/// Selenium standalone Chrome (Chrome 153, Grid 4.49.0).
pub const CHROME_IMAGE: (&str, &str) = ("selenium/standalone-chrome", "4.49.0");

/// The WebDriver endpoint of [`start_chrome`] (it shares the host network).
pub const CHROME_URL: &str = "http://localhost:4444";

/// A running Keycloak with the `mcp` realm from `keycloak-realm.json` imported.
pub struct Keycloak {
    pub container: ContainerAsync<GenericImage>,
    /// e.g. `http://127.0.0.1:32768`
    pub base: String,
}

impl Keycloak {
    /// The issuer of the `mcp` realm.
    pub fn realm(&self) -> String {
        format!("{}/realms/mcp", self.base)
    }

    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.realm())
    }

    pub fn oidc_endpoint(&self, name: &str) -> String {
        format!("{}/protocol/openid-connect/{}", self.realm(), name)
    }
}

pub async fn start_keycloak() -> anyhow::Result<Keycloak> {
    let realm_path = std::env::current_dir()?.join("keycloak-realm.json");
    let realm_path = realm_path.to_str().expect("utf-8 path").to_string();

    let container = GenericImage::new(KEYCLOAK_IMAGE.0, KEYCLOAK_IMAGE.1)
        .with_wait_for(WaitFor::message_on_stdout("Listening on:"))
        .with_env_var("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
        .with_env_var("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
        .with_mount(Mount::bind_mount(
            realm_path,
            "/opt/keycloak/data/import/realm.json",
        ))
        .with_cmd(["start-dev", "--import-realm"])
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start Keycloak (is Docker running?): {e:?}"))?;

    let port = container.get_host_port_ipv4(8080).await?;
    Ok(Keycloak {
        container,
        base: format!("http://127.0.0.1:{port}"),
    })
}

pub async fn start_chrome() -> anyhow::Result<ContainerAsync<GenericImage>> {
    GenericImage::new(CHROME_IMAGE.0, CHROME_IMAGE.1)
        .with_wait_for(WaitFor::message_on_stdout("Started Selenium Standalone"))
        .with_network("host")
        .start()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to start the Chrome container. Is Docker running and accessible? \
                 If you use a non-standard socket, set DOCKER_HOST \
                 (e.g. DOCKER_HOST=unix:///var/run/docker.sock). Error: {e:?}"
            )
        })
}

pub mod mcp_server;

use mcp_passport::config::Config;
use mcp_passport::vault::Vault;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};

/// A 2026-07-28 request with the required `_meta`.
pub fn modern(id: impl Into<Value>, method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": mcp_server::MODERN,
        "io.modelcontextprotocol/clientInfo": {"name": "mcp-passport-tests", "version": "1.0.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc": "2.0", "id": id.into(), "method": method, "params": params})
}

/// Parses CLI arguments into a Config (the binary name is added).
pub fn config(args: &[&str]) -> Config {
    let mut all = vec!["mcp-passport"];
    all.extend_from_slice(args);
    <Config as clap::Parser>::try_parse_from(all).expect("valid test config")
}

/// Drives `mcp_passport::run_with_vault` through its stdio, like an MCP client.
pub struct StdioClient {
    writer: DuplexStream,
    lines: Lines<BufReader<DuplexStream>>,
    run: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl StdioClient {
    pub fn start(config: Config, vault: Vault) -> Self {
        let (writer, server_in) = tokio::io::duplex(1 << 20);
        let (server_out, reader) = tokio::io::duplex(1 << 20);
        let run = tokio::spawn(mcp_passport::run_with_vault(
            config, vault, server_in, server_out,
        ));
        Self {
            writer,
            lines: BufReader::new(reader).lines(),
            run,
        }
    }

    pub async fn send(&mut self, msg: Value) {
        self.writer
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .expect("write to proxy stdin");
    }

    /// The next message from the proxy, or None after `wait`.
    pub async fn recv(&mut self, wait: Duration) -> Option<Value> {
        match tokio::time::timeout(wait, self.lines.next_line()).await {
            Ok(Ok(Some(line))) => Some(serde_json::from_str(&line).expect("proxy wrote JSON")),
            _ => None,
        }
    }

    /// Reads messages until the response with `id` arrives; returns it and the
    /// messages seen before it.
    pub async fn response(&mut self, id: impl Into<Value>, wait: Duration) -> (Value, Vec<Value>) {
        let id = id.into();
        let mut before = Vec::new();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let msg = self
                .recv(left)
                .await
                .unwrap_or_else(|| panic!("no response for id {id}; saw {before:?}"));
            if msg.get("id") == Some(&id) && msg.get("method").is_none() {
                return (msg, before);
            }
            before.push(msg);
        }
    }

    /// Sends a request and waits for its response.
    pub async fn call(&mut self, msg: Value, wait: Duration) -> Value {
        let id = msg["id"].clone();
        self.send(msg).await;
        self.response(id, wait).await.0
    }

    /// Closes stdin and waits for the proxy to exit.
    pub async fn close(self) -> anyhow::Result<()> {
        drop(self.writer);
        tokio::time::timeout(Duration::from_secs(15), self.run).await??
    }
}
