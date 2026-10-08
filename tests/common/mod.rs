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
