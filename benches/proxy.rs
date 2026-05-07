use criterion::{criterion_group, criterion_main, Criterion};
use mcp_passport::crypto::DpopKey;
use mcp_passport::vault::Vault;

fn criterion_benchmark(c: &mut Criterion) {
    let vault = Vault::new("bench_svc");
    std::env::set_var("MCP_PASSPORT_USE_MEMORY_VAULT", "1");
    let _ = vault.store_token("bench_user", "test_token_1234567890");
    let _ = vault.store_dpop_key("bench_user", &DpopKey::generate().to_bytes());

    c.bench_function("vault_uncached", |b| {
        b.iter(|| {
            let token = vault.get_token(std::hint::black_box("bench_user")).unwrap();
            let dpop_key = vault
                .get_dpop_key(std::hint::black_box("bench_user"))
                .unwrap();
            std::hint::black_box((token, dpop_key));
        })
    });

    let cached_token = vault.get_token("bench_user").unwrap();
    let cached_dpop_key = vault.get_dpop_key("bench_user").unwrap();

    c.bench_function("vault_cached", |b| {
        b.iter(|| {
            let token = cached_token.clone();
            let dpop_key = cached_dpop_key.clone();
            std::hint::black_box((token, dpop_key));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
