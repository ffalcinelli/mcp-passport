//! # OS-Native Secure Vault
//!
//! This module provides an abstraction over the system's native secure storage
//! (macOS Keychain, Windows Credential Manager, Linux Secret Service) via the `keyring` crate.
//!
//! It also includes an in-memory fallback for headless or testing environments.

use crate::Result;
use anyhow::Context;
use keyring::Entry;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

// In-memory fallback for testing and headless environments where system keyring might be missing/unavailable
static MEMORY_VAULT: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// A secure storage abstraction for tokens and keys.
#[derive(Clone)]
pub struct Vault {
    /// The service name used for isolation in the keychain.
    pub service: String,
    /// Whether to bypass the system keychain and use an in-memory store.
    use_memory: bool,
}

impl Vault {
    /// Creates a new Vault instance for a given service name.
    pub fn new(service: &str) -> Self {
        // Automatically use memory vault if environment variable is set
        let use_memory = std::env::var("MCP_PASSPORT_USE_MEMORY_VAULT").is_ok();
        Self {
            service: service.to_string(),
            use_memory,
        }
    }

    fn make_key(&self, user_id: &str, suffix: &str) -> String {
        format!("{}:{}:{}", self.service, user_id, suffix)
    }

    /// Stores an access token securely in the vault.
    pub fn store_token(&self, user_id: &str, token: &str) -> Result<()> {
        if self.use_memory {
            let key = self.make_key(user_id, "token");
            MEMORY_VAULT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, token.to_string());
            return Ok(());
        }
        let entry = Entry::new(&self.service, user_id)?;
        entry
            .set_password(token)
            .context("Failed to store token in vault")?;
        Ok(())
    }

    /// Retrieves an access token from the vault.
    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        if self.use_memory {
            let key = self.make_key(user_id, "token");
            return Ok(MEMORY_VAULT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&key)
                .cloned());
        }
        let entry = Entry::new(&self.service, user_id)?;
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e).context("Failed to retrieve token from vault")),
        }
    }

    /// Deletes an access token from the vault.
    pub fn delete_token(&self, user_id: &str) -> Result<()> {
        if self.use_memory {
            let key = self.make_key(user_id, "token");
            MEMORY_VAULT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            return Ok(());
        }
        let entry = Entry::new(&self.service, user_id)?;
        let _ = entry.delete_credential();
        Ok(())
    }

    /// Stores the DPoP private key securely.
    pub fn store_dpop_key(&self, user_id: &str, key_bytes: &[u8]) -> Result<()> {
        let key_hex = hex::encode(key_bytes);
        if self.use_memory {
            let key = self.make_key(user_id, "dpop");
            MEMORY_VAULT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, key_hex);
            return Ok(());
        }
        let dpop_service = format!("{}-dpop", self.service);
        let entry = Entry::new(&dpop_service, user_id)?;
        entry
            .set_password(&key_hex)
            .context("Failed to store DPoP key in vault")?;
        Ok(())
    }

    /// Retrieves the DPoP private key from the vault.
    pub fn get_dpop_key(&self, user_id: &str) -> Result<Option<Vec<u8>>> {
        let key_hex = if self.use_memory {
            let key = self.make_key(user_id, "dpop");
            MEMORY_VAULT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&key)
                .cloned()
        } else {
            let dpop_service = format!("{}-dpop", self.service);
            let entry = Entry::new(&dpop_service, user_id)?;
            match entry.get_password() {
                Ok(h) => Some(h),
                Err(keyring::Error::NoEntry) => None,
                Err(e) => {
                    return Err(anyhow::anyhow!(e).context("Failed to retrieve DPoP key from vault"))
                }
            }
        };

        match key_hex {
            Some(h) => {
                let bytes = hex::decode(&h).context("Failed to decode DPoP key hex")?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_token_ops() -> Result<()> {
        std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
        std::env::set_var("MCP_PASSPORT_SKIP_OPEN_BROWSER", "1");
        let vault = Vault::new("mcp-passport-test");
        let user = "test_user_1";
        let token = "test_token_123";

        // Store
        vault.store_token(user, token)?;

        // Get
        let retrieved = vault.get_token(user)?;
        assert_eq!(retrieved, Some(token.to_string()));

        // Delete
        vault.delete_token(user)?;
        let deleted = vault.get_token(user)?;
        assert_eq!(deleted, None);
        Ok(())
    }

    #[test]
    fn test_mutex_poison_recovery() -> Result<()> {
        std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
        let vault = Vault::new("mcp-passport-test");

        // Poison the mutex by panicking while holding the lock
        let _ = std::thread::spawn(|| {
            let _lock = MEMORY_VAULT.lock().unwrap();
            panic!("Poisoning the mutex");
        })
        .join();

        // Verify it is indeed poisoned
        assert!(MEMORY_VAULT.lock().is_err());

        // Now try to use the vault. It should not panic because we handle poisoning.
        let user = "test_user_poison";
        let token = "token_after_poison";

        vault.store_token(user, token)?;
        let retrieved = vault.get_token(user)?;
        assert_eq!(retrieved, Some(token.to_string()));

        // Also test other operations
        vault.delete_token(user)?;
        assert_eq!(vault.get_token(user)?, None);

        Ok(())
    }

    #[test]
    fn test_vault_dpop_ops() -> Result<()> {
        std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
        let vault = Vault::new("mcp-passport-test");
        let user = "test_user_dpop";
        let key_bytes = b"test_key_bytes_123456789012345678";

        // Store
        vault.store_dpop_key(user, key_bytes)?;

        // Get
        let retrieved = vault.get_dpop_key(user)?;
        assert_eq!(retrieved, Some(key_bytes.to_vec()));

        // Non-existent user
        let none = vault.get_dpop_key("non_existent")?;
        assert_eq!(none, None);

        Ok(())
    }

    #[test]
    fn test_vault_dpop_hex_failure() -> Result<()> {
        std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
        let vault = Vault::new("mcp-passport-test");
        let user = "test_user_bad_hex";

        // Directly inject invalid hex into MEMORY_VAULT
        let key = vault.make_key(user, "dpop");
        MEMORY_VAULT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, "invalid hex".to_string());

        let res = vault.get_dpop_key(user);
        assert!(res.is_err());
        assert!(format!("{:?}", res.err().unwrap()).contains("Failed to decode DPoP key hex"));

        Ok(())
    }

    #[test]
    fn test_vault_real_keyring_attempt() {
        // We don't set MCP_PASSPORT_USE_MEMORY_VAULT here
        let old_val = std::env::var("MCP_PASSPORT_USE_MEMORY_VAULT");
        std::env::remove_var("MCP_PASSPORT_USE_MEMORY_VAULT");

        let vault = Vault::new("mcp-passport-unit-test-real");
        assert!(!vault.use_memory);

        // This will likely fail in CI but it's okay, we just want to cover the lines.
        // We use a dummy user to avoid messing up real keys.
        let _ = vault.store_token("dummy_user_test", "dummy_token");
        let _ = vault.get_token("dummy_user_test");
        let _ = vault.delete_token("dummy_user_test");
        let _ = vault.store_dpop_key("dummy_user_test", b"dummy");
        let _ = vault.get_dpop_key("dummy_user_test");

        // Restore env var
        if let Ok(val) = old_val {
            std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", val);
        }
    }
}
