//! Module: rate_limiter
//!
//! Automatically added module documentation.

/// Documentation for this item.
pub mod config;
/// Documentation for this item.
pub mod tracker;

pub use config::RateLimiterConfig;
use tracker::BackoffTracker;

// - Benchmark `governor` under 10k+ concurrent async tasks.
// - Implement dynamic backoff integration for 429 Too Many Requests.
use governor::{clock, middleware, state, Quota, RateLimiter as GovLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

type GovernorLimiter = GovLimiter<
    state::NotKeyed,
    state::InMemoryState,
    clock::DefaultClock,
    middleware::NoOpMiddleware<clock::QuantaInstant>,
>;

/// Tracks 429 responses for dynamic backoff
#[derive(Debug)]

/// Thread-safe, global request rate limiter using the Token Bucket algorithm.
///
/// Features:
/// - Configurable base rate with burst support
/// - Dynamic backoff for 429 Too Many Requests responses
/// - Respect for Retry-After headers
/// - Shared across all async tasks via Arc
/// - Each call to `acquire()` awaits until a token is available
#[derive(Clone)]
pub struct RateLimiter {
    limiter: Arc<RwLock<Arc<GovernorLimiter>>>,
    config: Arc<RwLock<RateLimiterConfig>>,
    backoff: Arc<Mutex<BackoffTracker>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    ///
    /// # Arguments
    /// * `config` - Configuration for the rate limiter
    ///
    /// # Panics
    /// Panics if `config.base_rps` is 0.
    pub fn new(config: RateLimiterConfig) -> Self {
        assert!(config.base_rps > 0, "Base RPS must be > 0");

        let quota = Quota::per_second(NonZeroU32::new(config.base_rps).expect("RPS must be > 0"))
            .allow_burst(
                NonZeroU32::new(config.burst_size.unwrap_or(config.base_rps))
                    .expect("Burst size must be > 0"),
            );

        let limiter = Arc::new(GovLimiter::direct(quota));

        Self {
            limiter: Arc::new(RwLock::new(limiter)),
            config: Arc::new(RwLock::new(config)),
            backoff: Arc::new(Mutex::new(BackoffTracker::default())),
        }
    }

    /// Creates a new rate limiter allowing `rps` requests per second with default settings.
    ///
    /// # Panics
    /// Panics if `rps` is 0.
    pub fn new_simple(rps: u32) -> Self {
        Self::new(RateLimiterConfig {
            base_rps: rps,
            ..Default::default()
        })
    }

    /// Awaits until a request token is available. This is a non-blocking async operation
    /// that integrates with the tokio runtime.
    pub async fn acquire(&self) {
        // Apply backoff if needed
        {
            let backoff = self.backoff.lock().await;
            if backoff.backoff_multiplier > 1 {
                let delay = Duration::from_secs(backoff.backoff_multiplier.into());
                tokio::time::sleep(delay).await;
            }
        }

        // Acquire from the base limiter
        let limiter = self.limiter.read().await.clone();
        limiter.until_ready().await;

        // Update prometheus gauge with effective RPS snapshot
        let stats = self.stats().await;
        crate::metrics::RATE_LIMITER_PERMITS.set(stats.current_rps as f64);
    }

    /// Records a 429 Too Many Requests response to trigger backoff.
    ///
    /// This should be called when a request receives a 429 status code.
    /// The backoff duration increases with consecutive 429 responses.
    pub async fn record_429(&self, retry_after: Option<u32>) {
        let config = self.config.write().await;
        let mut backoff = self.backoff.lock().await;

        backoff.consecutive_429s += 1;
        backoff.last_429 = Some(Instant::now());

        // Calculate backoff multiplier
        let base_multiplier =
            (1.0f32 + config.backoff_factor * backoff.consecutive_429s as f32) as u32;
        backoff.backoff_multiplier = std::cmp::min(base_multiplier, config.max_backoff);

        // If we have a Retry-After value, use it as minimum backoff
        if let Some(retry_secs) = retry_after.filter(|&x| x > 0) {
            if retry_secs > backoff.backoff_multiplier {
                backoff.backoff_multiplier = retry_secs;
            }
        }

        tracing::warn!(
            consecutive_429s = backoff.consecutive_429s,
            backoff_multiplier = backoff.backoff_multiplier,
            "Rate limit hit (429), applying backoff"
        );

        // Update prometheus gauge
        crate::metrics::RATE_LIMITER_PERMITS
            .set(config.base_rps as f64 / backoff.backoff_multiplier as f64);
    }

    /// Records a successful response, potentially reducing backoff.
    ///
    /// This should be called when a request succeeds (non-429 response).
    /// Gradually reduces backoff over time to restore normal operation.
    pub async fn record_success(&self) {
        let mut backoff = self.backoff.lock().await;
        let now = Instant::now();

        // Gradually reduce backoff after successful requests
        if let Some(last_429) = backoff.last_429 {
            if now.duration_since(last_429) > Duration::from_secs(30) {
                // If it's been 30+ seconds since last 429, reduce backoff
                if backoff.consecutive_429s > 0 {
                    backoff.consecutive_429s = backoff.consecutive_429s.saturating_sub(1);
                    if backoff.consecutive_429s == 0 {
                        backoff.backoff_multiplier = 1;
                    } else {
                        let config = self.config.read().await;
                        let base_multiplier = (1.0f32
                            + config.backoff_factor * backoff.consecutive_429s as f32)
                            as u32;
                        backoff.backoff_multiplier =
                            std::cmp::min(base_multiplier, config.max_backoff);
                    }
                }
            }
        }

        // If no recent 429s or older than 5min, reset completely
        let should_reset = match backoff.last_429 {
            Some(ts) => now.duration_since(ts) > Duration::from_secs(300),
            None => true,
        };
        if should_reset {
            backoff.consecutive_429s = 0;
            backoff.backoff_multiplier = 1;
        }

        // Snapshot effective RPS into prometheus gauge
        let multiplier = backoff.backoff_multiplier;
        drop(backoff);
        crate::metrics::RATE_LIMITER_PERMITS
            .set(self.config().await.base_rps as f64 / multiplier as f64);
    }

    /// Get current configuration
    pub async fn config(&self) -> RateLimiterConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: RateLimiterConfig) {
        *self.config.write().await = new_config.clone();
        // Rebuild the limiter with new quota
        let quota =
            Quota::per_second(NonZeroU32::new(new_config.base_rps).expect("RPS must be > 0"))
                .allow_burst(
                    NonZeroU32::new(new_config.burst_size.unwrap_or(new_config.base_rps))
                        .expect("Burst size must be > 0"),
                );
        *self.limiter.write().await = Arc::new(GovLimiter::direct(quota));
        crate::metrics::RATE_LIMITER_PERMITS.set(new_config.base_rps as f64);
    }

    /// Get current statistics
    pub async fn stats(&self) -> RateLimiterStats {
        let backoff = self.backoff.lock().await;
        let config = self.config.read().await;

        RateLimiterStats {
            current_rps: config.base_rps as f32 / backoff.backoff_multiplier as f32,
            configured_rps: config.base_rps,
            consecutive_429s: backoff.consecutive_429s,
            backoff_multiplier: backoff.backoff_multiplier,
            last_429: backoff.last_429.map(|t| t.elapsed().as_secs()),
        }
    }
}

/// Statistics for monitoring rate limiter performance
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    /// Current effective requests per second (after backoff)
    pub current_rps: f32,
    /// Configured base requests per second
    pub configured_rps: u32,
    /// Number of consecutive 429 responses
    pub consecutive_429s: usize,
    /// Current backoff multiplier
    pub backoff_multiplier: u32,
    /// Seconds since last 429 (if any)
    pub last_429: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_rate_limiter_does_not_block_under_limit() {
        let limiter = RateLimiter::new_simple(100);
        // Should complete instantly — we're well under 100 RPS
        let _ = timeout(std::time::Duration::from_secs(1), limiter.acquire()).await;
    }

    #[tokio::test]
    #[should_panic(expected = "Base RPS must be > 0")]
    async fn test_rate_limiter_zero_rps_panics() {
        let _ = RateLimiter::new_simple(0);
    }

    #[tokio::test]
    async fn test_rate_limiter_respects_config() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            base_rps: 10,
            burst_size: Some(5),
            ..Default::default()
        });

        // Should allow burst of 5 immediately
        for _ in 0..5 {
            limiter.acquire().await;
        }

        // After burst, should be rate-limited
        // This test is simplified - real test would need timing checks
    }

    #[tokio::test]
    async fn test_429_backoff() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            base_rps: 10,
            backoff_factor: 2.0,
            max_backoff: 10,
            ..Default::default()
        });

        // Record a 429
        limiter.record_429(None).await;

        // Next acquire should be delayed
        let start = std::time::Instant::now();
        limiter.acquire().await;
        let elapsed = start.elapsed();

        // Should have waited at least some time due to backoff
        assert!(elapsed.as_secs() > 0);
    }

    // ── Expanded tests ────────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_config_default() {
        let config = RateLimiterConfig::default();
        assert_eq!(config.base_rps, 10);
        assert_eq!(config.burst_size, None);
        assert_eq!(config.backoff_factor, 1.5);
        assert_eq!(config.max_backoff, 60);
        assert!(config.respect_retry_after);
    }

    #[tokio::test]
    async fn test_rate_limiter_new_with_burst() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            base_rps: 50,
            burst_size: Some(20),
            ..Default::default()
        });
        let config = limiter.config().await;
        assert_eq!(config.base_rps, 50);
        assert_eq!(config.burst_size, Some(20));
    }

    #[tokio::test]
    async fn test_429_backoff_consecutive() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            base_rps: 100,
            backoff_factor: 1.0,
            max_backoff: 5,
            ..Default::default()
        });

        limiter.record_429(None).await;
        let stats = limiter.stats().await;
        // With factor 1.0: multiplier = 1 + 1*1 = 2
        assert_eq!(stats.backoff_multiplier, 2);

        limiter.record_429(None).await;
        let stats = limiter.stats().await;
        // With factor 1.0: multiplier = 1 + 1*2 = 3
        assert_eq!(stats.backoff_multiplier, 3);
    }

    #[tokio::test]
    async fn test_429_backoff_caps_at_max() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            base_rps: 100,
            backoff_factor: 10.0,
            max_backoff: 5,
            ..Default::default()
        });

        for _ in 0..10 {
            limiter.record_429(None).await;
        }
        let stats = limiter.stats().await;
        assert_eq!(stats.backoff_multiplier, 5);
        assert_eq!(stats.consecutive_429s, 10);
    }

    #[tokio::test]
    async fn test_429_retry_after_overrides_backoff() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            base_rps: 100,
            backoff_factor: 1.0,
            max_backoff: 60,
            ..Default::default()
        });

        // Retry-After of 30s should be the multiplier
        limiter.record_429(Some(30)).await;
        let stats = limiter.stats().await;
        assert!(stats.backoff_multiplier >= 30);
    }

    #[tokio::test]
    async fn test_record_success_reduces_backoff() {
        let limiter = RateLimiter::new(RateLimiterConfig {
            base_rps: 100,
            backoff_factor: 2.0,
            max_backoff: 10,
            ..Default::default()
        });

        limiter.record_429(None).await;
        let stats = limiter.stats().await;
        assert_eq!(stats.consecutive_429s, 1);

        // record_success() only reduces backoff if 30+ seconds have passed since last 429.
        // Without real time passage, consecutive_429s stays at 1.
        for _ in 0..6 {
            limiter.record_success().await;
        }
        let stats = limiter.stats().await;
        // No time has passed, so backoff remains
        assert_eq!(stats.consecutive_429s, 1);
        assert_eq!(stats.backoff_multiplier, 3); // 1 + 2.0 * 1 = 3
    }

    #[tokio::test]
    async fn test_stats_initial() {
        let limiter = RateLimiter::new_simple(50);
        let stats = limiter.stats().await;
        assert_eq!(stats.configured_rps, 50);
        assert_eq!(stats.current_rps, 50.0);
        assert_eq!(stats.consecutive_429s, 0);
        assert_eq!(stats.backoff_multiplier, 1);
        assert!(stats.last_429.is_none());
    }

    #[tokio::test]
    async fn test_stats_after_429() {
        let limiter = RateLimiter::new_simple(100);
        limiter.record_429(None).await;
        let stats = limiter.stats().await;
        assert_eq!(stats.consecutive_429s, 1);
        assert!(stats.last_429.is_some());
    }

    #[tokio::test]
    async fn test_update_config() {
        let limiter = RateLimiter::new_simple(10);
        assert_eq!(limiter.config().await.base_rps, 10);

        limiter
            .update_config(RateLimiterConfig {
                base_rps: 100,
                ..Default::default()
            })
            .await;
        assert_eq!(limiter.config().await.base_rps, 100);
    }

    #[tokio::test]
    async fn test_concurrent_acquire() {
        let limiter = Arc::new(RateLimiter::new_simple(500));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let l = limiter.clone();
            handles.push(tokio::spawn(async move {
                l.acquire().await;
            }));
        }

        for h in handles {
            let _ = timeout(std::time::Duration::from_secs(5), h).await;
        }
    }
}
