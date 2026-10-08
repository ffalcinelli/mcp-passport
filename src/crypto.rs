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
    /// Server-provided nonce (RFC 9449 §8, §9).
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
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
    pub fn public_jwk(&self) -> Result<Value> {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        let encoded_point = verifying_key.to_encoded_point(false);

        Ok(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(encoded_point.x().context("P-256 must have x")?),
            "y": URL_SAFE_NO_PAD.encode(encoded_point.y().context("P-256 must have y")?),
        }))
    }

    /// The RFC 7638 JWK thumbprint of the public key (the DPoP `jkt`).
    pub fn jkt(&self) -> Result<String> {
        let jwk = self.public_jwk()?;
        let coord = |k: &str| {
            jwk[k]
                .as_str()
                .map(str::to_string)
                .context("missing JWK coordinate")
        };
        Ok(ec_thumbprint(&coord("x")?, &coord("y")?))
    }

    /// Generates a DPoP Proof JWT for a given HTTP method and URL.
    /// Optional access_token can be provided to include 'ath' claim.
    pub fn generate_proof(&self, htm: &str, htu: &str) -> Result<String> {
        self.generate_proof_with_ath(htm, htu, None, None)
    }

    /// Generates a DPoP Proof JWT, optionally with an access token hash (`ath`)
    /// and a server-provided `nonce`.
    pub fn generate_proof_with_ath(
        &self,
        htm: &str,
        htu: &str,
        access_token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<String> {
        let jwk = self.public_jwk()?;

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
            htu: normalize_htu(htu),
            iat: now,
            ath,
            nonce: nonce.map(str::to_string),
        };

        let header_str = serde_json::to_string(&header)?;
        let claims_str = serde_json::to_string(&claims)?;

        // Pre-allocate buffer for the JWT message (header + '.' + payload)
        // Base64 encoding size is roughly 4/3 of the input size
        let header_len = (header_str.len() * 4).div_ceil(3);
        let claims_len = (claims_str.len() * 4).div_ceil(3);
        let mut message = String::with_capacity(header_len + 1 + claims_len);

        URL_SAFE_NO_PAD.encode_string(header_str.as_bytes(), &mut message);
        message.push('.');
        URL_SAFE_NO_PAD.encode_string(claims_str.as_bytes(), &mut message);

        let signature: p256::ecdsa::Signature = self.signing_key.sign(message.as_bytes());

        // Pre-allocate buffer for the final JWT (message + '.' + signature)
        let sig_len = 86; // approximate length of base64url encoded P-256 signature
        let mut final_jwt = String::with_capacity(message.len() + 1 + sig_len);
        final_jwt.push_str(&message);
        final_jwt.push('.');
        URL_SAFE_NO_PAD.encode_string(signature.to_bytes(), &mut final_jwt);

        Ok(final_jwt)
    }
}

/// RFC 7638 thumbprint of a P-256 key: SHA-256 over the required members in
/// lexicographic order, without whitespace.
fn ec_thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The `DPoP-Nonce` response header, if present (RFC 9449 §8.1).
pub fn dpop_nonce(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// The `htu` claim is the target URI without query and fragment (RFC 9449 §4.2).
fn normalize_htu(htu: &str) -> String {
    match url::Url::parse(htu) {
        Ok(mut u) if u.query().is_some() || u.fragment().is_some() => {
            u.set_query(None);
            u.set_fragment(None);
            u.into()
        }
        _ => htu.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_thumbprint_rfc9449_example() {
        // RFC 9449 §6.1 / §10: the example key and its jkt.
        assert_eq!(
            ec_thumbprint(
                "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
            ),
            "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        );
    }

    #[test]
    fn test_jkt_matches_proof_jwk() -> Result<()> {
        let key = DpopKey::generate();
        let proof = key.generate_proof("POST", "https://as/token")?;
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(proof.split('.').next().unwrap())?)?;
        let jwk = &header["jwk"];
        assert_eq!(
            key.jkt()?,
            ec_thumbprint(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap())
        );
        assert_eq!(key.jkt()?.len(), 43);
        Ok(())
    }

    #[test]
    fn test_normalize_htu() {
        assert_eq!(
            normalize_htu("https://api.example.com/rpc?session=1#frag"),
            "https://api.example.com/rpc"
        );
        assert_eq!(
            normalize_htu("https://api.example.com/rpc"),
            "https://api.example.com/rpc"
        );
        assert_eq!(normalize_htu("not a url"), "not a url");
    }

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
    fn test_public_jwk() -> Result<()> {
        let key = DpopKey::generate();
        let jwk = key.public_jwk()?;
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk.get("x").is_some());
        assert!(jwk.get("y").is_some());
        Ok(())
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
    fn test_generate_proof_success() -> Result<()> {
        let key = DpopKey::generate();
        let proof = key.generate_proof("GET", "https://api.example.com/resource")?;

        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "Proof must have 3 parts");

        let claims_json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert_eq!(claims_json["htm"], "GET");
        assert_eq!(claims_json["htu"], "https://api.example.com/resource");

        // Assert that 'ath' claim is not present when calling generate_proof (wrapper without ath)
        assert!(
            claims_json.get("ath").is_none(),
            "ath claim should not be present in wrapper generate_proof"
        );

        Ok(())
    }

    #[test]
    fn test_generate_proof_signature() -> Result<()> {
        use p256::ecdsa::signature::Verifier;

        let key = DpopKey::generate();
        let htm = "POST";
        let htu = "https://api.example.com/rpc";
        let proof = key.generate_proof(htm, htu)?;
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let message = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
        let signature = p256::ecdsa::Signature::from_slice(&sig_bytes)?;

        let verifying_key = VerifyingKey::from(&key.signing_key);
        verifying_key
            .verify(message.as_bytes(), &signature)
            .expect("Signature verification failed");

        let claims_json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert_eq!(claims_json["htm"], htm);
        assert_eq!(claims_json["htu"], htu);

        Ok(())
    }

    #[test]
    fn test_generate_proof_with_nonce() -> Result<()> {
        let key = DpopKey::generate();
        let decode = |proof: String| -> Result<Value> {
            let claims = proof.split('.').nth(1).unwrap().to_string();
            Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims)?)?)
        };

        let with =
            decode(key.generate_proof_with_ath("POST", "https://as/token", None, Some("n-1"))?)?;
        assert_eq!(with["nonce"], "n-1");
        let without = decode(key.generate_proof("POST", "https://as/token")?)?;
        assert!(without.get("nonce").is_none());
        Ok(())
    }

    #[test]
    fn test_generate_proof_with_ath() -> Result<()> {
        let key = DpopKey::generate();
        let access_token = "test_token";
        let proof = key.generate_proof_with_ath(
            "GET",
            "https://api.example.com/sse",
            Some(access_token),
            None,
        )?;
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header_json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
        assert_eq!(header_json["typ"], "dpop+jwt");
        assert_eq!(header_json["alg"], "ES256");
        assert!(header_json.get("jwk").is_some());

        let claims_json: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        assert_eq!(claims_json["htm"], "GET");
        assert_eq!(claims_json["htu"], "https://api.example.com/sse");
        assert!(claims_json.get("jti").is_some());
        assert!(claims_json.get("iat").is_some());
        assert!(claims_json.get("ath").is_some());

        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let expected_ath = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(claims_json["ath"], expected_ath);
        Ok(())
    }
}
