use keyring::Entry;
use crate::Result;
use anyhow::Context;

pub struct Vault {
    service: String,
}

impl Vault {
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
        }
    }

    pub fn store_token(&self, user_id: &str, token: &str) -> Result<()> {
        let entry = Entry::new(&self.service, user_id)?;
        entry.set_password(token).context("Failed to store token in vault")?;
        Ok(())
    }

    pub fn get_token(&self, user_id: &str) -> Result<Option<String>> {
        let entry = Entry::new(&self.service, user_id)?;
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e).context("Failed to retrieve token from vault")),
        }
    }

    pub fn delete_token(&self, user_id: &str) -> Result<()> {
        let entry = Entry::new(&self.service, user_id)?;
        entry.delete_password().context("Failed to delete token from vault")?;
        Ok(())
    }

    /// Stores the DPoP private key as hex string
    pub fn store_dpop_key(&self, user_id: &str, key_bytes: &[u8]) -> Result<()> {
        let dpop_service = format!("{}-dpop", self.service);
        let entry = Entry::new(&dpop_service, user_id)?;
        let key_hex = hex::encode(key_bytes);
        entry.set_password(&key_hex).context("Failed to store DPoP key in vault")?;
        Ok(())
    }

    /// Retrieves the DPoP private key bytes
    pub fn get_dpop_key(&self, user_id: &str) -> Result<Option<Vec<u8>>> {
        let dpop_service = format!("{}-dpop", self.service);
        let entry = Entry::new(&dpop_service, user_id)?;
        match entry.get_password() {
            Ok(key_hex) => {
                let bytes = hex::decode(&key_hex).context("Failed to decode DPoP key hex")?;
                Ok(Some(bytes))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e).context("Failed to retrieve DPoP key from vault")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_token_ops() -> Result<()> {
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
    fn test_vault_dpop_key_ops() -> Result<()> {
        let vault = Vault::new("mcp-passport-test");
        let user = "test_user_2";
        let key_bytes = b"0123456789abcdef0123456789abcdef";

        // Store
        vault.store_dpop_key(user, key_bytes)?;

        // Get
        let retrieved = vault.get_dpop_key(user)?;
        assert_eq!(retrieved, Some(key_bytes.to_vec()));

        // Cleanup (keyring doesn't have a direct delete for dpop key in our wrapper yet, but we can add it if needed)
        Ok(())
    }
}
