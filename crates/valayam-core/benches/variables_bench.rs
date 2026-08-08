use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use valayam_engine::variables::{
    build_initial_context, extract_placeholder_names, resolve_variables, resolve_variables_advanced,
};

fn bench_resolve_variables_basic(c: &mut Criterion) {
    let mut ctx = HashMap::new();
    ctx.insert("BaseURL".to_string(), "https://example.com".to_string());
    ctx.insert("token".to_string(), "abc123def456".to_string());
    ctx.insert("Hostname".to_string(), "example.com".to_string());

    let input = "{{BaseURL}}/api/v2/scan?token={{token}}&host={{Hostname}}";

    c.bench_function("variables_resolve_basic", |b| {
        b.iter(|| {
            let _ = black_box(resolve_variables(black_box(input), black_box(&ctx)));
        });
    });
}

fn bench_resolve_variables_large_context(c: &mut Criterion) {
    let mut ctx = HashMap::with_capacity(200);
    for i in 0..200 {
        ctx.insert(format!("var_{}", i), format!("value_{}_data", i));
    }
    let input = (0..100)
        .map(|i| format!("{{{{var_{}}}}}", i))
        .collect::<Vec<_>>()
        .join(",");

    c.bench_function("variables_resolve_large_context", |b| {
        b.iter(|| {
            let _ = black_box(resolve_variables(black_box(&input), black_box(&ctx)));
        });
    });
}

fn bench_resolve_variables_no_match(c: &mut Criterion) {
    let ctx = HashMap::new();
    c.bench_function("variables_resolve_no_placeholders", |b| {
        b.iter(|| {
            let _ = black_box(resolve_variables(
                black_box("plain string without variables"),
                black_box(&ctx),
            ));
        });
    });
}

fn bench_resolve_variables_missing(c: &mut Criterion) {
    let ctx = HashMap::new();
    let input = "{{missing1}} {{missing2}} {{missing3}} {{missing4}}";

    c.bench_function("variables_resolve_all_missing", |b| {
        b.iter(|| {
            let _ = black_box(resolve_variables(black_box(input), black_box(&ctx)));
        });
    });
}

fn bench_resolve_advanced(c: &mut Criterion) {
    let mut ctx = HashMap::new();
    ctx.insert("name".to_string(), "john".to_string());
    ctx.insert("domain".to_string(), "example.com".to_string());

    c.bench_function("variables_resolve_advanced_upper", |b| {
        b.iter(|| {
            let _ = black_box(resolve_variables_advanced(
                black_box("{{name|upper}}@{{domain}}"),
                black_box(&ctx),
            ));
        });
    });

    c.bench_function("variables_resolve_advanced_default", |b| {
        b.iter(|| {
            let _ = black_box(resolve_variables_advanced(
                black_box("Hello {{missing|default:\"Guest\"}}!"),
                black_box(&ctx),
            ));
        });
    });

    c.bench_function("variables_resolve_advanced_chained", |b| {
        b.iter(|| {
            let _ = black_box(resolve_variables_advanced(
                black_box("{{name|upper|reverse|trim}}"),
                black_box(&ctx),
            ));
        });
    });
}

fn bench_build_initial_context(c: &mut Criterion) {
    c.bench_function("variables_build_initial_context", |b| {
        b.iter(|| {
            let _ = black_box(build_initial_context(
                black_box("https://scan.target.com:8443/api/v3/"),
                black_box("scan.target.com"),
            ));
        });
    });
}

fn bench_extract_placeholder_names(c: &mut Criterion) {
    let input =
        "Bearer {{auth_token}} on {{BaseURL}} with {{timeout|default:\"30s\"}} and {{retries}}";

    c.bench_function("variables_extract_placeholder_names", |b| {
        b.iter(|| {
            let _ = black_box(extract_placeholder_names(black_box(input)));
        });
    });
}

criterion_group! {
    name = variables_benches;
    config = Criterion::default();
    targets = bench_resolve_variables_basic, bench_resolve_variables_large_context, bench_resolve_variables_no_match, bench_resolve_variables_missing, bench_resolve_advanced, bench_build_initial_context, bench_extract_placeholder_names
}
criterion_main!(variables_benches);
