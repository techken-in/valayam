use std::time::Instant;

#[derive(Debug)]
#[non_exhaustive]
/// Documentation for this item.
pub struct BackoffTracker {
    /// Documentation for this item.
    pub consecutive_429s: usize,
    /// Documentation for this item.
    pub last_429: Option<Instant>,
    /// Documentation for this item.
    pub backoff_multiplier: u32,
}

impl BackoffTracker {
    /// Create a new BackoffTracker.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for BackoffTracker {
    fn default() -> Self {
        Self {
            consecutive_429s: 0,
            last_429: None,
            backoff_multiplier: 1,
        }
    }
}
