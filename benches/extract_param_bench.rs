use criterion::{criterion_group, criterion_main, Criterion};

fn extract_param_original(header: &str, param: &str) -> Option<String> {
    let needle = format!("{}=", param);
    if let Some(start) = header.find(&needle) {
        let val_start = start + needle.len();
        let remainder = &header[val_start..];
        if let Some(stripped) = remainder.strip_prefix('"') {
            if let Some(end) = stripped.find('"') {
                return Some(stripped[..end].to_string());
            }
        } else {
            // Unquoted: take until comma or end of string
            let end = remainder.find(',').unwrap_or(remainder.len());
            return Some(remainder[..end].trim().to_string());
        }
    }
    None
}

fn extract_param_optimized(header: &str, param: &str) -> Option<String> {
    let mut start = 0;
    while let Some(pos) = header[start..].find(param) {
        let absolute_pos = start + pos;
        let after_param = &header[absolute_pos + param.len()..];
        if let Some(remainder) = after_param.strip_prefix('=') {
            if let Some(stripped) = remainder.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    return Some(stripped[..end].to_string());
                }
            } else {
                let end = remainder.find(',').unwrap_or(remainder.len());
                return Some(remainder[..end].trim().to_string());
            }
        }
        start = absolute_pos + 1;
    }
    None
}

fn criterion_benchmark(c: &mut Criterion) {
    let header = "Bearer realm=\"example\", error=\"invalid_token\", error_description=\"The access token expired\"";

    c.bench_function("extract_param_original", |b| {
        b.iter(|| {
            let res = extract_param_original(
                std::hint::black_box(header),
                std::hint::black_box("error")
            );
            std::hint::black_box(res);
        })
    });

    c.bench_function("extract_param_optimized", |b| {
        b.iter(|| {
            let res = extract_param_optimized(
                std::hint::black_box(header),
                std::hint::black_box("error")
            );
            std::hint::black_box(res);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
