use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

fn criterion_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let rwlock_val = Arc::new(RwLock::new(0u64));
    c.bench_function("reauth_count_rwlock_read", |b| {
        // Just blocking on the runtime instead of async bench feature
        b.iter(|| {
            rt.block_on(async {
                let val = { *rwlock_val.read().await };
                std::hint::black_box(val);
            });
        })
    });

    let atomic_val = Arc::new(AtomicU64::new(0));
    c.bench_function("reauth_count_atomic_read", |b| {
        b.iter(|| {
            let val = atomic_val.load(Ordering::Relaxed);
            std::hint::black_box(val);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
