#[derive(Debug, Clone)]
/// Documentation for this item.
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
