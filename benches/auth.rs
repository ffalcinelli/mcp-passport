use criterion::{criterion_group, criterion_main, Criterion};

fn auth_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dir = std::env::temp_dir();

    rt.block_on(async {
        let success_path = dir.join("success.html");
        let failure_path = dir.join("failure.html");
        tokio::fs::write(&success_path, "<html>success</html>").await.unwrap();
        tokio::fs::write(&failure_path, "<html>failure</html>").await.unwrap();
    });

    c.bench_function("template_load_sequential", |b| {
        b.iter(|| {
            rt.block_on(async {
                let success_html = tokio::fs::read_to_string(dir.join("success.html")).await.unwrap();
                let failure_html = tokio::fs::read_to_string(dir.join("failure.html")).await.unwrap();
                std::hint::black_box((success_html, failure_html));
            })
        })
    });

    c.bench_function("template_load_concurrent", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (success_res, failure_res) = tokio::join!(
                    tokio::fs::read_to_string(dir.join("success.html")),
                    tokio::fs::read_to_string(dir.join("failure.html"))
                );
                std::hint::black_box((success_res.unwrap(), failure_res.unwrap()));
            })
        })
    });
}

criterion_group!(benches, auth_benchmark);
criterion_main!(benches);
