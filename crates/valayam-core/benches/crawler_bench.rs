use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use tokio::runtime::Runtime;
use valayam_crawler::Crawler;
use valayam_engine::rate_limiter::RateLimiter;
use valayam_network::network::http::StealthHttpClient;

fn crawler_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // We only benchmark the initialization and memory structures for now,
    // since a full crawl involves real network I/O which fluctuates wildly.
    // In a real environment, we'd mock the StealthHttpClient.

    c.bench_function("crawler_init", |b| {
        b.iter(|| {
            rt.block_on(async {
                let http_client =
                    Arc::new(StealthHttpClient::new(false, false, None, false).unwrap());
                let rate_limiter = Some(Arc::new(RateLimiter::new_simple(100)));

                let _crawler =
                    Crawler::new(http_client, "http://localhost:8081", 3, rate_limiter, None)
                        .unwrap();
            })
        });
    });
}

criterion_group!(benches, crawler_benchmark);
criterion_main!(benches);
