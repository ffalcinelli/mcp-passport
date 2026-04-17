use keyring::Entry;
use crate::Result;
use anyhow::Context;
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

// In-memory fallback for testing and headless environments where system keyring might be missing/unavailable
static MEMORY_VAULT: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
pub struct Vault {
    pub service: String,
    use_memory: bool,
}

impl Vault {
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

    pub fn store_token(&self, user_id: &str, token: &str) -> Result<()> {
        if self.use_memory {
            let key = self.make_key(user_id, "token");
            MEMORY_VAULT.lock().unwrap().insert(key, token.to_string());
            return Ok(());
        }
        let entry = Entry::new(&self.service, user_id)?;
        entry.set_password(token).context("Failed to store token in vault")?;
        Ok(())
    }

    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        if self.use_memory {
            let key = self.make_key(user_id, "token");
            return Ok(MEMORY_VAULT.lock().unwrap().get(&key).cloned());
        }
        let entry = Entry::new(&self.service, user_id)?;
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e).context("Failed to retrieve token from vault")),
        }
    }

    pub fn delete_token(&self, user_id: &str) -> Result<()> {
        if self.use_memory {
            let key = self.make_key(user_id, "token");
            MEMORY_VAULT.lock().unwrap().remove(&key);
            return Ok(());
        }
        let entry = Entry::new(&self.service, user_id)?;
        let _ = entry.delete_credential();
        Ok(())
    }

    /// Stores the DPoP private key as hex string
    pub fn store_dpop_key(&self, user_id: &str, key_bytes: &[u8]) -> Result<()> {
        let key_hex = hex::encode(key_bytes);
        if self.use_memory {
            let key = self.make_key(user_id, "dpop");
            MEMORY_VAULT.lock().unwrap().insert(key, key_hex);
            return Ok(());
        }
        let dpop_service = format!("{}-dpop", self.service);
        let entry = Entry::new(&dpop_service, user_id)?;
        entry.set_password(&key_hex).context("Failed to store DPoP key in vault")?;
        Ok(())
    }

    /// Retrieves the DPoP private key bytes
    pub fn get_dpop_key(&self, user_id: &str) -> Result<Option<Vec<u8>>> {
        let key_hex = if self.use_memory {
            let key = self.make_key(user_id, "dpop");
            MEMORY_VAULT.lock().unwrap().get(&key).cloned()
        } else {
            let dpop_service = format!("{}-dpop", self.service);
            let entry = Entry::new(&dpop_service, user_id)?;
            match entry.get_password() {
                Ok(h) => Some(h),
                Err(keyring::Error::NoEntry) => None,
                Err(e) => return Err(anyhow::anyhow!(e).context("Failed to retrieve DPoP key from vault")),
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
}
