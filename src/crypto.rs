//! # DPoP Cryptographic Primitives
//!
//! This module provides the implementation of **Demonstrating Proof-of-Possession** (DPoP)
//! as per [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
//!
//! It handles:
//! - P-256 key pair generation.
//! - DPoP-signed JWT generation.
//! - SHA-256 hashing of access tokens for the `ath` claim.

use crate::Result;
use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
use p256::SecretKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// An ephemeral P-256 key pair used for signing DPoP proofs.
pub struct DpopKey {
    /// The ECDSA signing key.
    signing_key: SigningKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

impl DpopKey {
    /// Generates a new ephemeral DPoP keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { signing_key }
    }

    /// Restores a DPoP keypair from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::from_slice(bytes).context("Invalid DPoP key bytes")?;
        let signing_key = SigningKey::from(secret_key);
        Ok(Self { signing_key })
    }

    /// Exports the private key as bytes for secure storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Constructs the public JWK representation.
    pub fn public_jwk(&self) -> Value {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);

        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(encoded_point.x().expect("P-256 must have x")),
            "y": URL_SAFE_NO_PAD.encode(encoded_point.y().expect("P-256 must have y")),
        })
    }

    /// Generates a DPoP Proof JWT for a given HTTP method and URL.
    /// Optional access_token can be provided to include 'ath' claim.
    pub fn generate_proof(&self, htm: &str, htu: &str) -> Result<String> {
        self.generate_proof_with_ath(htm, htu, None)
    }

    /// Generates a DPoP Proof JWT with an access token hash (ath).
    pub fn generate_proof_with_ath(
        &self,
        htm: &str,
        htu: &str,
        access_token: Option<&str>,
    ) -> Result<String> {
        let jwk = self.public_jwk();

        let header = json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk
        });

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let ath = access_token.map(|at| {
            let mut hasher = Sha256::new();
            hasher.update(at.as_bytes());
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        });

        let claims = DpopClaims {
            jti: Uuid::new_v4().to_string(),
            htm: htm.to_string(),
            htu: htu.to_string(),
            iat: now,
            ath,
        };

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims)?);

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature: p256::ecdsa::Signature = self.signing_key.sign(message.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", message, signature_b64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpop_key_generate_and_bytes() -> Result<()> {
        let key = DpopKey::generate();
        let bytes = key.to_bytes();
        assert_eq!(bytes.len(), 32);

        let key2 = DpopKey::from_bytes(&bytes)?;
        assert_eq!(key.to_bytes(), key2.to_bytes());
        Ok(())
    }

    #[test]
    fn test_dpop_key_invalid_bytes() {
        let res = DpopKey::from_bytes(&[1, 2, 3]);
        assert!(res.is_err());
        assert!(format!("{:?}", res.err().unwrap()).contains("Invalid DPoP key bytes"));
    }

    #[test]
    fn test_public_jwk() {
        let key = DpopKey::generate();
        let jwk = key.public_jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk.get("x").is_some());
        assert!(jwk.get("y").is_some());
    }

    #[test]
    fn test_generate_proof() -> Result<()> {
        let key = DpopKey::generate();
        let proof = key.generate_proof("POST", "https://api.example.com/rpc")?;
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
        assert_eq!(header_json["typ"], "dpop+jwt");
        assert_eq!(header_json["alg"], "ES256");
        assert!(header_json.get("jwk").is_some());

        let claims_json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert_eq!(claims_json["htm"], "POST");
        assert_eq!(claims_json["htu"], "https://api.example.com/rpc");
        assert!(claims_json.get("jti").is_some());
        assert!(claims_json.get("iat").is_some());
        Ok(())
    }

    #[test]
    fn test_generate_proof_with_ath() -> Result<()> {
        let key = DpopKey::generate();
        let access_token = "test_token";
        let proof =
            key.generate_proof_with_ath("GET", "https://api.example.com/sse", Some(access_token))?;
        let parts: Vec<&str> = proof.split('.').collect();

        let claims_json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert!(claims_json.get("ath").is_some());

        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let expected_ath = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(claims_json["ath"], expected_ath);
        Ok(())
    }
}
