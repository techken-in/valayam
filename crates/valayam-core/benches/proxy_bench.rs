use criterion::{black_box, criterion_group, criterion_main, Criterion};
use valayam_core::stealth::proxy::ProxyRotator;

fn bench_proxy_new_empty(c: &mut Criterion) {
    c.bench_function("proxy_new_empty", |b| {
        b.iter(|| {
            black_box(ProxyRotator::new());
        });
    });
}

fn bench_proxy_round_robin(c: &mut Criterion) {
    let mut rotator = ProxyRotator::new();
    // Register 20 proxies via load_from_file semantics — we build via the API
    for i in 0..20 {
        let address = format!("http://proxy{}:8080", i);
        rotator.record_success(&address);
    }
    // Manually populate proxies since record_success won't add new ones
    // Use a proxy file approach instead
    let content: String = (0..20)
        .map(|i| format!("http://proxy{}:8080", i))
        .collect::<Vec<_>>()
        .join("\n");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxies.txt");
    std::fs::write(&path, &content).unwrap();
    let rotator = ProxyRotator::load_from_file(path.to_str().unwrap()).unwrap();

    c.bench_function("proxy_next_round_robin", |b| {
        b.iter(|| {
            black_box(rotator.next());
        });
    });

    c.bench_function("proxy_random", |b| {
        b.iter(|| {
            black_box(rotator.random());
        });
    });
}

fn bench_proxy_large_pool(c: &mut Criterion) {
    let content: String = (0..1000)
        .map(|i| format!("socks5://proxy{}:1080", i))
        .collect::<Vec<_>>()
        .join("\n");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxies.txt");
    std::fs::write(&path, &content).unwrap();
    let rotator = ProxyRotator::load_from_file(path.to_str().unwrap()).unwrap();

    c.bench_function("proxy_next_large_pool_1000", |b| {
        b.iter(|| {
            black_box(rotator.next());
        });
    });
}

fn bench_proxy_record_operations(c: &mut Criterion) {
    let content = "http://proxy1:8080\nhttp://proxy2:8080\nhttp://proxy3:8080\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxies.txt");
    std::fs::write(&path, content).unwrap();
    let mut rotator = ProxyRotator::load_from_file(path.to_str().unwrap()).unwrap();

    c.bench_function("proxy_record_failure", |b| {
        b.iter(|| {
            rotator.record_failure(black_box("http://proxy1:8080"));
        });
    });

    c.bench_function("proxy_record_latency", |b| {
        b.iter(|| {
            rotator.record_latency(black_box("http://proxy1:8080"), black_box(150));
        });
    });

    c.bench_function("proxy_healthy_proxies", |b| {
        b.iter(|| {
            black_box(rotator.healthy_proxies());
        });
    });
}

fn bench_proxy_load_from_file(c: &mut Criterion) {
    let content = (0..100)
        .map(|i| format!("http://proxy{}:8080", i))
        .collect::<Vec<_>>()
        .join("\n");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxies.txt");
    std::fs::write(&path, &content).unwrap();
    let path_str = path.to_str().unwrap().to_string();

    c.bench_function("proxy_load_from_file_100", |b| {
        b.iter(|| {
            black_box(ProxyRotator::load_from_file(black_box(&path_str)).unwrap());
        });
    });
}

criterion_group! {
    name = proxy_benches;
    config = Criterion::default();
    targets = bench_proxy_new_empty, bench_proxy_round_robin, bench_proxy_large_pool, bench_proxy_record_operations, bench_proxy_load_from_file
}
criterion_main!(proxy_benches);
