use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn scopes_original(scopes: Option<Vec<String>>) -> String {
    let mut s_vec = if let Some(ref s) = scopes {
        s.clone()
    } else {
        vec![]
    };
    if !s_vec.contains(&"openid".to_string()) {
        s_vec.push("openid".to_string());
    }
    s_vec.join(" ")
}

fn scopes_optimized(scopes: Option<Vec<String>>) -> String {
    let mut s_vec = scopes.unwrap_or_default();
    let openid = "openid";
    if !s_vec.iter().any(|s| s == openid) {
        s_vec.push(openid.to_string());
    }
    s_vec.join(" ")
}

fn scopes_benchmark(c: &mut Criterion) {
    c.bench_function("scopes_original_none", |b| {
        b.iter(|| scopes_original(black_box(None)))
    });
    c.bench_function("scopes_optimized_none", |b| {
        b.iter(|| scopes_optimized(black_box(None)))
    });

    c.bench_function("scopes_original_some_without_openid", |b| {
        b.iter(|| {
            scopes_original(black_box(Some(vec![
                "profile".to_string(),
                "email".to_string(),
            ])))
        })
    });
    c.bench_function("scopes_optimized_some_without_openid", |b| {
        b.iter(|| {
            scopes_optimized(black_box(Some(vec![
                "profile".to_string(),
                "email".to_string(),
            ])))
        })
    });
}

criterion_group!(benches, scopes_benchmark);
criterion_main!(benches);
