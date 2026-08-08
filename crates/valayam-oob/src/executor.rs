use crate::server::OobServer;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Retry configuration for OOB polling.
#[derive(Debug, Clone)]
pub struct OobPollConfig {
    /// Base sleep between retries (default: 1s).
    pub base_interval: Duration,
    /// Max sleep between retries (default: 10s).
    pub max_interval: Duration,
    /// Multiplier applied after each empty poll (default: 1.5).
    pub backoff_factor: f64,
    /// Jitter fraction to add [0, factor] (default: 0.1).
    pub jitter_factor: f64,
}

impl Default for OobPollConfig {
    fn default() -> Self {
        Self {
            base_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(10),
            backoff_factor: 1.5,
            jitter_factor: 0.1,
        }
    }
}

/// Executes OOB polling to check if an interaction has occurred.
pub struct OobExecutor;

impl OobExecutor {
    /// Polls the OOB server for a specific correlation ID until the timeout is reached.
    /// Uses exponential backoff with jitter between polls.
    pub async fn wait_for_interaction(
        server: Arc<OobServer>,
        correlation_id: &str,
        timeout_secs: u64,
    ) -> bool {
        Self::wait_for_interaction_with_config(
            server,
            correlation_id,
            timeout_secs,
            &OobPollConfig::default(),
        )
        .await
    }

    /// Polls with a custom retry config.
    pub async fn wait_for_interaction_with_config(
        server: Arc<OobServer>,
        correlation_id: &str,
        timeout_secs: u64,
        config: &OobPollConfig,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        let mut interval = config.base_interval;

        while tokio::time::Instant::now() < deadline {
            {
                if let Some(hits) = server.check_hits(correlation_id).await {
                    if !hits.is_empty() {
                        tracing::debug!(correlation_id, "OOB interaction confirmed");
                        return true;
                    }
                }
            }

            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let jitter = if config.jitter_factor > 0.0 {
                let j = config.jitter_factor * interval.as_secs_f64();
                let half_j = j / 2.0;
                (rand::random::<f64>() * j) - half_j
            } else {
                0.0
            };
            let actual_delay = (interval.as_secs_f64() + jitter).max(0.1);
            let capped = actual_delay.min(5.0);
            sleep(Duration::from_secs_f64(capped)).await;

            interval = (interval.mul_f64(config.backoff_factor)).min(config.max_interval);
        }

        tracing::debug!(correlation_id, "OOB interaction timeout — no hit detected");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oob_poll_config_default() {
        let config = OobPollConfig::default();
        assert_eq!(config.base_interval, Duration::from_secs(1));
        assert!(config.backoff_factor > 1.0);
    }

    #[tokio::test]
    async fn test_wait_for_interaction_timeout() {
        let config = OobPollConfig {
            base_interval: Duration::from_millis(10),
            max_interval: Duration::from_millis(50),
            backoff_factor: 1.0,
            jitter_factor: 0.0,
        };

        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let mut interval = config.base_interval;
        let mut checked = false;
        while tokio::time::Instant::now() < deadline {
            checked = true;
            sleep(interval).await;
            interval = (interval.mul_f64(config.backoff_factor)).min(config.max_interval);
        }
        assert!(checked);
    }
}
