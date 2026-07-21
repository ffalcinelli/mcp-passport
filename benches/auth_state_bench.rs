use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AuthServerStateString {
    #[allow(dead_code)]
    expected_state: String,
    #[allow(dead_code)]
    tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    #[allow(dead_code)]
    success_html: String,
    #[allow(dead_code)]
    failure_html: String,
    #[allow(dead_code)]
    issuer_name: String,
    #[allow(dead_code)]
    resource_name: String,
}

#[derive(Clone)]
struct AuthServerStateArc {
    #[allow(dead_code)]
    expected_state: String,
    #[allow(dead_code)]
    tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    #[allow(dead_code)]
    success_html: Arc<String>,
    #[allow(dead_code)]
    failure_html: Arc<String>,
    #[allow(dead_code)]
    issuer_name: String,
    #[allow(dead_code)]
    resource_name: String,
}

fn bench_state_clone(c: &mut Criterion) {
    let large_html = "<html>".to_string() + &"a".repeat(100_000) + "</html>";
    let (tx, _rx) = oneshot::channel();
    let tx_arc = Arc::new(Mutex::new(Some(tx)));

    let state_string = AuthServerStateString {
        expected_state: "state".to_string(),
        tx: tx_arc.clone(),
        success_html: large_html.clone(),
        failure_html: large_html.clone(),
        issuer_name: "Issuer".to_string(),
        resource_name: "Resource".to_string(),
    };

    let state_arc = AuthServerStateArc {
        expected_state: "state".to_string(),
        tx: tx_arc.clone(),
        success_html: Arc::new(large_html.clone()),
        failure_html: Arc::new(large_html.clone()),
        issuer_name: "Issuer".to_string(),
        resource_name: "Resource".to_string(),
    };

    let mut group = c.benchmark_group("AuthServerState Clone");
    group.bench_function("String", |b| {
        b.iter(|| {
            std::hint::black_box(state_string.clone());
        });
    });

    group.bench_function("Arc", |b| {
        b.iter(|| {
            std::hint::black_box(state_arc.clone());
        });
    });
    group.finish();
}

criterion_group!(benches, bench_state_clone);
criterion_main!(benches);
