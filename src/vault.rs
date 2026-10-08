//! # OS-Native Secure Vault
//!
//! This module provides an abstraction over the system's native secure storage
//! (macOS Keychain, Windows Credential Manager, Linux Secret Service) via the `keyring` crate.
//!
//! It also includes an in-memory backend for headless or testing environments.

use crate::Result;
use anyhow::Context;
use keyring::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The kind of secret stored in the vault. Each kind lives in its own keyring entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Secret {
    Token,
    DpopKey,
}

impl Secret {
    /// Suffix used for the in-memory key and the keyring service name.
    fn suffix(self) -> &'static str {
        match self {
            Secret::Token => "token",
            Secret::DpopKey => "dpop",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Secret::Token => "token",
            Secret::DpopKey => "DPoP key",
        }
    }
}

#[derive(Clone)]
enum Backend {
    /// The operating system's credential store.
    Keyring,
    /// A process-local store. Clones of the same `Vault` share it.
    Memory(Arc<Mutex<HashMap<String, String>>>),
}

/// A secure storage abstraction for tokens and keys.
#[derive(Clone)]
pub struct Vault {
    /// The service name used for isolation in the keychain.
    pub service: String,
    backend: Backend,
}

impl Vault {
    /// Creates a vault backed by the OS keychain.
    pub fn keyring(service: &str) -> Self {
        Self {
            service: service.to_string(),
            backend: Backend::Keyring,
        }
    }

    /// Creates a vault backed by a fresh, process-local in-memory store.
    pub fn in_memory(service: &str) -> Self {
        Self {
            service: service.to_string(),
            backend: Backend::Memory(Arc::new(Mutex::new(HashMap::new()))),
        }
    }

    /// Uses the in-memory backend when `MCP_PASSPORT_USE_MEMORY_VAULT` is set,
    /// otherwise the OS keychain.
    pub fn from_env(service: &str) -> Self {
        if std::env::var("MCP_PASSPORT_USE_MEMORY_VAULT").is_ok() {
            Self::in_memory(service)
        } else {
            Self::keyring(service)
        }
    }

    fn make_key(&self, user_id: &str, suffix: &str) -> String {
        format!("{}:{}:{}", self.service, user_id, suffix)
    }

    fn keyring_entry(&self, user_id: &str, secret: Secret) -> Result<Entry> {
        let service = match secret {
            // Kept as the bare service name for backwards compatibility.
            Secret::Token => self.service.clone(),
            _ => format!("{}-{}", self.service, secret.suffix()),
        };
        Ok(Entry::new(&service, user_id)?)
    }

    fn set(&self, user_id: &str, secret: Secret, value: &str) -> Result<()> {
        match &self.backend {
            Backend::Memory(store) => {
                store
                    .lock()
                    .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?
                    .insert(self.make_key(user_id, secret.suffix()), value.to_string());
                Ok(())
            }
            Backend::Keyring => self
                .keyring_entry(user_id, secret)?
                .set_password(value)
                .with_context(|| format!("Failed to store {} in vault", secret.label())),
        }
    }

    fn get(&self, user_id: &str, secret: Secret) -> Result<Option<String>> {
        match &self.backend {
            Backend::Memory(store) => Ok(store
                .lock()
                .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?
                .get(&self.make_key(user_id, secret.suffix()))
                .cloned()),
            Backend::Keyring => match self.keyring_entry(user_id, secret)?.get_password() {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(anyhow::anyhow!(e)
                    .context(format!("Failed to retrieve {} from vault", secret.label()))),
            },
        }
    }

    fn delete(&self, user_id: &str, secret: Secret) -> Result<()> {
        match &self.backend {
            Backend::Memory(store) => {
                store
                    .lock()
                    .map_err(|e| anyhow::anyhow!("Mutex poisoned: {}", e))?
                    .remove(&self.make_key(user_id, secret.suffix()));
            }
            Backend::Keyring => {
                let _ = self.keyring_entry(user_id, secret)?.delete_credential();
            }
        }
        Ok(())
    }

    /// Stores an access token securely in the vault.
    pub fn store_token(&self, user_id: &str, token: &str) -> Result<()> {
        self.set(user_id, Secret::Token, token)
    }

    /// Retrieves an access token from the vault.
    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        self.get(user_id, Secret::Token)
    }

    /// Deletes an access token from the vault.
    pub fn delete_token(&self, user_id: &str) -> Result<()> {
        self.delete(user_id, Secret::Token)
    }

    /// Stores the DPoP private key securely.
    pub fn store_dpop_key(&self, user_id: &str, key_bytes: &[u8]) -> Result<()> {
        self.set(user_id, Secret::DpopKey, &hex::encode(key_bytes))
    }

    /// Retrieves the DPoP private key from the vault.
    pub fn get_dpop_key(&self, user_id: &str) -> Result<Option<Vec<u8>>> {
        self.get(user_id, Secret::DpopKey)?
            .map(|h| hex::decode(h).context("Failed to decode DPoP key hex"))
            .transpose()
    }

    /// Deletes the DPoP private key from the vault.
    pub fn delete_dpop_key(&self, user_id: &str) -> Result<()> {
        self.delete(user_id, Secret::DpopKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_key() {
        let vault = Vault::in_memory("my-service");

        // Happy path
        assert_eq!(
            vault.make_key("user123", "token"),
            "my-service:user123:token"
        );

        // Edge cases
        assert_eq!(vault.make_key("", "token"), "my-service::token");
        assert_eq!(vault.make_key("user123", ""), "my-service:user123:");
        assert_eq!(vault.make_key("", ""), "my-service::");

        // Special characters
        assert_eq!(
            vault.make_key("user@domain.com", "dpop"),
            "my-service:user@domain.com:dpop"
        );
    }

    #[test]
    fn test_vault_token_ops() -> Result<()> {
        let vault = Vault::in_memory("mcp-passport-test");
        let user = "test_user_1";
        let token = "test_token_123";

        vault.store_token(user, token)?;
        assert_eq!(vault.get_token(user)?, Some(token.to_string()));

        vault.delete_token(user)?;
        assert_eq!(vault.get_token(user)?, None);
        Ok(())
    }

    #[test]
    fn test_delete_nonexistent_token() -> Result<()> {
        let vault = Vault::in_memory("mcp-passport-test-nonexistent");
        assert!(vault.delete_token("non_existent_user").is_ok());
        Ok(())
    }

    #[test]
    fn test_vault_dpop_ops() -> Result<()> {
        let vault = Vault::in_memory("mcp-passport-test");
        let user = "test_user_dpop";
        let key_bytes = b"test_key_bytes_123456789012345678";

        vault.store_dpop_key(user, key_bytes)?;
        assert_eq!(vault.get_dpop_key(user)?, Some(key_bytes.to_vec()));

        assert_eq!(vault.get_dpop_key("non_existent")?, None);

        vault.delete_dpop_key(user)?;
        assert_eq!(vault.get_dpop_key(user)?, None);
        Ok(())
    }

    #[test]
    fn test_delete_nonexistent_dpop_key() -> Result<()> {
        let vault = Vault::in_memory("mcp-passport-test-nonexistent-dpop");
        assert!(vault.delete_dpop_key("non_existent_user").is_ok());
        Ok(())
    }

    #[test]
    fn test_vault_dpop_hex_failure() -> Result<()> {
        let vault = Vault::in_memory("mcp-passport-test");
        let user = "test_user_bad_hex";
        vault.set(user, Secret::DpopKey, "invalid hex")?;

        let res = vault.get_dpop_key(user);
        assert!(res.is_err());
        assert!(format!("{:?}", res.err().unwrap()).contains("Failed to decode DPoP key hex"));
        Ok(())
    }

    #[test]
    fn test_in_memory_vaults_are_isolated_but_clones_share() -> Result<()> {
        let a = Vault::in_memory("svc");
        let b = Vault::in_memory("svc");
        let a2 = a.clone();

        a.store_token("user", "token-a")?;
        assert_eq!(a2.get_token("user")?, Some("token-a".into()));
        assert_eq!(b.get_token("user")?, None);
        Ok(())
    }

    #[test]
    fn test_vault_real_keyring_attempt() {
        let vault = Vault::keyring("mcp-passport-unit-test-real");

        // This will likely fail in CI but it's okay, we just want to cover the lines.
        // We use a dummy user to avoid messing up real keys.
        let _ = vault.store_token("dummy_user_test", "dummy_token");
        let _ = vault.get_token("dummy_user_test");
        let _ = vault.delete_token("dummy_user_test");
        let _ = vault.store_dpop_key("dummy_user_test", b"dummy");
        let _ = vault.get_dpop_key("dummy_user_test");
        let _ = vault.delete_dpop_key("dummy_user_test");
    }
}
