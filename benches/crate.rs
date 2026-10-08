//! Benchmarks of the per-request hot paths of mcp-passport.

use criterion::{criterion_group, criterion_main, Criterion};
use mcp_passport::crypto::DpopKey;
use mcp_passport::vault::Vault;
use std::hint::black_box;

const HTU: &str = "https://mcp.example.com/mcp";
const TOKEN: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJzdWIiOiJqZG9lIn0.c2lnbmF0dXJl";

/// A DPoP proof is signed for every request sent to the MCP server.
fn dpop_proofs(c: &mut Criterion) {
    let key = DpopKey::generate();
    let mut group = c.benchmark_group("dpop_proof");
    group.bench_function("plain", |b| {
        b.iter(|| {
            key.generate_proof(black_box("POST"), black_box(HTU))
                .unwrap()
        })
    });
    group.bench_function("with_ath", |b| {
        b.iter(|| {
            key.generate_proof_with_ath(black_box("POST"), black_box(HTU), Some(TOKEN), None)
                .unwrap()
        })
    });
    group.bench_function("with_ath_and_nonce", |b| {
        b.iter(|| {
            key.generate_proof_with_ath("POST", HTU, Some(TOKEN), Some("server-nonce-1"))
                .unwrap()
        })
    });
    group.bench_function("restore_key_from_bytes", |b| {
        let bytes = key.to_bytes();
        b.iter(|| DpopKey::from_bytes(black_box(&bytes)).unwrap())
    });
    group.finish();
}

/// Credentials are reloaded from the vault after every re-authentication.
fn vault(c: &mut Criterion) {
    let vault = Vault::in_memory("bench");
    vault.store_token("user", TOKEN).unwrap();
    vault
        .store_dpop_key("user", &DpopKey::generate().to_bytes())
        .unwrap();

    c.bench_function("vault_in_memory_load_credentials", |b| {
        b.iter(|| {
            let token = vault.get_token(black_box("user")).unwrap();
            let key = vault.get_dpop_key(black_box("user")).unwrap();
            black_box((token, key))
        })
    });
}

criterion_group!(benches, dpop_proofs, vault);
criterion_main!(benches);
