#[derive(Debug, Clone)]
/// Documentation for this item.
#[non_exhaustive]
pub struct RateLimiterConfig {
    /// Documentation for this item.
    pub base_rps: u32,
    /// Documentation for this item.
    pub burst_size: Option<u32>,
    /// Documentation for this item.
    pub backoff_factor: f32,
    /// Documentation for this item.
    pub max_backoff: u32,
    /// Documentation for this item.
    pub respect_retry_after: bool,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            base_rps: 10,
            burst_size: None,
            backoff_factor: 1.5,
            max_backoff: 60,
            respect_retry_after: true,
        }
    }
}

impl RateLimiterConfig {
    /// Create a new RateLimiterConfig.
    pub fn new(base_rps: u32) -> Self {
        Self {
            base_rps,
            ..Self::default()
        }
    }

    pub fn with_burst_size(mut self, burst_size: Option<u32>) -> Self {
        self.burst_size = burst_size;
        self
    }

    pub fn with_backoff_factor(mut self, factor: f32) -> Self {
        self.backoff_factor = factor;
        self
    }

    pub fn with_max_backoff(mut self, max_backoff: u32) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    pub fn with_respect_retry_after(mut self, respect: bool) -> Self {
        self.respect_retry_after = respect;
        self
    }
}
