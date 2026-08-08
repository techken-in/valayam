use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;
use valayam_engine::rate_limiter::{RateLimiter, RateLimiterConfig};

fn bench_rate_limiter_new(c: &mut Criterion) {
    c.bench_function("rate_limiter_new_simple_100", |b| {
        b.iter(|| {
            black_box(RateLimiter::new_simple(black_box(100)));
        });
    });

    c.bench_function("rate_limiter_new_custom_config", |b| {
        b.iter(|| {
            black_box(RateLimiter::new(RateLimiterConfig {
                base_rps: 500,
                burst_size: Some(100),
                backoff_factor: 2.0,
                max_backoff: 30,
                respect_retry_after: true,
            }));
        });
    });
}

fn bench_rate_limiter_acquire(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("rate_limiter_acquire_high_rps", |b| {
        let limiter = RateLimiter::new_simple(10_000);
        b.to_async(&rt).iter(|| async {
            limiter.acquire().await;
        });
    });
}

fn bench_rate_limiter_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("rate_limiter_stats_idle", |b| {
        let limiter = RateLimiter::new_simple(100);
        b.to_async(&rt).iter(|| async {
            black_box(limiter.stats().await);
        });
    });
}

fn bench_rate_limiter_429_backoff(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("rate_limiter_record_429", |b| {
        let limiter = RateLimiter::new_simple(100);
        b.to_async(&rt).iter(|| async {
            limiter.record_429(None).await;
        });
    });

    c.bench_function("rate_limiter_retry_after_override", |b| {
        let limiter = RateLimiter::new_simple(100);
        b.to_async(&rt).iter(|| async {
            limiter.record_429(Some(black_box(5))).await;
        });
    });
}

fn bench_rate_limiter_update_config(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("rate_limiter_update_config", |b| {
        let limiter = RateLimiter::new_simple(100);
        b.to_async(&rt).iter(|| async {
            limiter
                .update_config(RateLimiterConfig {
                    base_rps: black_box(200),
                    ..Default::default()
                })
                .await;
        });
    });
}

criterion_group! {
    name = rate_limiter_benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_rate_limiter_new, bench_rate_limiter_acquire, bench_rate_limiter_stats, bench_rate_limiter_429_backoff, bench_rate_limiter_update_config
}
criterion_main!(rate_limiter_benches);
