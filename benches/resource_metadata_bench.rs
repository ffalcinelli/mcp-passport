use criterion::{criterion_group, criterion_main, Criterion};

fn unoptimized_logic(resource: &String) -> String {
    // Simulate failing condition returning default
    resource.clone()
}

fn optimized_logic(resource: String) -> String {
    // Simulate failing condition returning default
    resource
}

fn criterion_benchmark(c: &mut Criterion) {
    let resource = "http://example.com/api".to_string();
    c.bench_function("unoptimized_resource_fallback", |b| {
        b.iter(|| unoptimized_logic(&resource))
    });
    c.bench_function("optimized_resource_fallback", |b| {
        b.iter(|| optimized_logic(resource.clone()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
