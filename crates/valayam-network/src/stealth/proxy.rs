use rand::seq::SliceRandom;
use rand::thread_rng;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Represents the health status of a proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHealth {
    /// Proxy is working normally
    Healthy,
    /// Proxy is degraded (slow or intermittent failures)
    Degraded,
    /// Proxy is unavailable (failed health check)
    Unavailable,
}

/// A single proxy entry with health tracking.
#[derive(Debug, Clone)]
struct ProxyEntry {
    /// Proxy URL in `protocol://host:port` format
    address: String,
    /// Current health status
    health: ProxyHealth,
    /// When the last health check was performed
    last_checked: Option<Instant>,
    /// Number of consecutive failures
    consecutive_failures: u32,
    /// Average response latency (if measured)
    avg_latency_ms: Option<u64>,
}

/// Internal state of the proxy rotator
#[derive(Clone)]
struct ProxyState {
    proxies: Vec<ProxyEntry>,
    index: usize,
}

/// Manages a pool of proxy addresses for rotation with health checking.
///
/// Supports SOCKS5 and HTTP proxies in `protocol://host:port` format.
/// Proxies are shuffled and returned in round-robin order, with automatic
/// skipping of unhealthy proxies.
#[derive(Clone)]
pub struct ProxyRotator {
    state: Arc<RwLock<ProxyState>>,
    /// Maximum consecutive failures before marking a proxy unhealthy
    max_failures: u32,
    /// Time after which to retry an unhealthy proxy
    retry_interval: Duration,
}

impl ProxyRotator {
    /// Create a new empty `ProxyRotator` (no proxies).
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ProxyState {
                proxies: Vec::new(),
                index: 0,
            })),
            max_failures: 3,
            retry_interval: Duration::from_secs(60),
        }
    }

    /// Loads proxies from a file (one per line).
    /// Empty lines and lines starting with `#` are skipped.
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read proxy file '{}': {}", path, e))?;

        let addresses: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

        if addresses.is_empty() {
            return Err("Proxy file is empty or contains no valid entries".to_string());
        }

        let proxies: Vec<ProxyEntry> = addresses
            .into_iter()
            .map(|address| ProxyEntry {
                address,
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            })
            .collect();

        Ok(Self {
            state: Arc::new(RwLock::new(ProxyState { proxies, index: 0 })),
            max_failures: 3,
            retry_interval: Duration::from_secs(60),
        })
    }

    /// Set the maximum consecutive failures before marking a proxy as unavailable.
    pub fn with_max_failures(mut self, max: u32) -> Self {
        self.max_failures = max;
        self
    }

    /// Set the retry interval for unhealthy proxies.
    pub fn with_retry_interval(mut self, interval: Duration) -> Self {
        self.retry_interval = interval;
        self
    }

    /// Returns the next healthy proxy in round-robin order.
    /// Skips unavailable proxies that haven't passed their retry interval.
    /// Returns `None` if no healthy proxies are available.
    pub async fn next(&self) -> Option<String> {
        let mut state = self.state.write().await;
        let len = state.proxies.len();
        if len == 0 {
            return None;
        }

        let start = state.index;
        state.index = (state.index + 1) % len;

        for i in 0..len {
            let idx = (start + i) % len;
            if self.is_proxy_usable(&state.proxies[idx]) {
                return Some(state.proxies[idx].address.clone());
            }
        }

        // All proxies are unavailable — return the first one anyway as a last resort
        state.proxies.first().map(|p| p.address.clone())
    }

    /// Returns a randomly selected healthy proxy.
    /// Returns `None` if no proxies are available at all.
    pub async fn random(&self) -> Option<String> {
        let state = self.state.read().await;
        if state.proxies.is_empty() {
            return None;
        }

        // Collect healthy proxies
        let healthy: Vec<&ProxyEntry> = state
            .proxies
            .iter()
            .filter(|p| self.is_proxy_usable(p))
            .collect();

        if healthy.is_empty() {
            // All proxies unavailable — return the first one as last resort
            return state.proxies.first().map(|p| p.address.clone());
        }

        let mut rng = thread_rng();
        healthy.choose(&mut rng).map(|p| p.address.clone())
    }

    /// Check if a proxy is usable (healthy or due for retry).
    fn is_proxy_usable(&self, entry: &ProxyEntry) -> bool {
        match entry.health {
            ProxyHealth::Healthy | ProxyHealth::Degraded => true,
            ProxyHealth::Unavailable => {
                // Retry if enough time has passed
                if let Some(last) = entry.last_checked {
                    last.elapsed() >= self.retry_interval
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful connection through a proxy.
    /// This improves the proxy's health score.
    pub async fn record_success(&self, address: &str) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.proxies.iter_mut().find(|p| p.address == address) {
            entry.consecutive_failures = 0;
            entry.health = ProxyHealth::Healthy;
            entry.last_checked = Some(Instant::now());
        }
    }

    /// Record a failure for a proxy.
    /// After `max_failures` consecutive failures, the proxy is marked unavailable.
    pub async fn record_failure(&self, address: &str) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.proxies.iter_mut().find(|p| p.address == address) {
            entry.consecutive_failures += 1;
            entry.last_checked = Some(Instant::now());

            if entry.consecutive_failures >= self.max_failures {
                entry.health = ProxyHealth::Unavailable;
            } else if entry.consecutive_failures >= (self.max_failures / 2).max(1) {
                entry.health = ProxyHealth::Degraded;
            }
        }
    }

    /// Record latency measurement for a proxy.
    pub async fn record_latency(&self, address: &str, latency_ms: u64) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.proxies.iter_mut().find(|p| p.address == address) {
            // Exponential moving average: new = old * 0.7 + sample * 0.3
            entry.avg_latency_ms = Some(match entry.avg_latency_ms {
                Some(avg) => (avg * 7 + latency_ms * 3) / 10,
                None => latency_ms,
            });
        }
    }

    /// Get the list of healthy proxy addresses.
    pub async fn healthy_proxies(&self) -> Vec<String> {
        let state = self.state.read().await;
        state
            .proxies
            .iter()
            .filter(|p| p.health == ProxyHealth::Healthy)
            .map(|p| p.address.clone())
            .collect()
    }

    /// Get the list of addresses for all proxies (regardless of health).
    pub async fn all_addresses(&self) -> Vec<String> {
        let state = self.state.read().await;
        state.proxies.iter().map(|p| p.address.clone()).collect()
    }

    /// Returns the number of proxies in the pool.
    pub async fn len(&self) -> usize {
        self.state.read().await.proxies.len()
    }

    /// Returns true if the proxy pool is empty.
    pub async fn is_empty(&self) -> bool {
        self.state.read().await.proxies.is_empty()
    }

    /// Reset all proxies to healthy status.
    pub async fn reset_health(&self) {
        let mut state = self.state.write().await;
        for entry in &mut state.proxies {
            entry.health = ProxyHealth::Healthy;
            entry.consecutive_failures = 0;
            entry.last_checked = None;
        }
    }

    /// Spawns a background task that periodically fetches fresh proxies from the given API.
    pub fn start_dynamic_updater(&self, api_url: String, refresh_interval: Duration) {
        let state = self.state.clone();

        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let mut interval = tokio::time::interval(refresh_interval);

            loop {
                interval.tick().await;
                info!("Fetching dynamic proxies from API: {}", api_url);

                match client.get(&api_url).send().await {
                    Ok(response) => {
                        if let Ok(text) = response.text().await {
                            let new_addresses: Vec<String> = text
                                .lines()
                                .map(|l| l.trim().to_string())
                                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                                .collect();

                            if new_addresses.is_empty() {
                                warn!("Dynamic proxy API returned empty or invalid response");
                                continue;
                            }

                            let mut locked_state = state.write().await;
                            // Keep existing proxies to preserve their health scores, add new ones
                            let mut updated_proxies = std::mem::take(&mut locked_state.proxies);

                            for addr in new_addresses {
                                if !updated_proxies.iter().any(|p| p.address == addr) {
                                    updated_proxies.push(ProxyEntry {
                                        address: addr,
                                        health: ProxyHealth::Healthy,
                                        last_checked: None,
                                        consecutive_failures: 0,
                                        avg_latency_ms: None,
                                    });
                                }
                            }

                            locked_state.proxies = updated_proxies;
                            info!(
                                "Successfully updated proxy pool. Total proxies: {}",
                                locked_state.proxies.len()
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to fetch dynamic proxies: {}", e);
                    }
                }
            }
        });
    }
}

impl Default for ProxyRotator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_rotator() {
        let rotator = ProxyRotator::new();
        assert!(rotator.is_empty().await);
        assert_eq!(rotator.len().await, 0);
        assert!(rotator.next().await.is_none());
        assert!(rotator.random().await.is_none());
    }

    #[tokio::test]
    async fn test_round_robin() {
        let rotator = ProxyRotator::new();
        {
            let mut state = rotator.state.write().await;
            state.proxies = vec![
                ProxyEntry {
                    address: "http://proxy1:8080".to_string(),
                    health: ProxyHealth::Healthy,
                    last_checked: None,
                    consecutive_failures: 0,
                    avg_latency_ms: None,
                },
                ProxyEntry {
                    address: "http://proxy2:8080".to_string(),
                    health: ProxyHealth::Healthy,
                    last_checked: None,
                    consecutive_failures: 0,
                    avg_latency_ms: None,
                },
            ];
        }

        assert_eq!(rotator.next().await, Some("http://proxy1:8080".to_string()));
        assert_eq!(rotator.next().await, Some("http://proxy2:8080".to_string()));
        assert_eq!(rotator.next().await, Some("http://proxy1:8080".to_string()));
        // wraps
    }

    #[tokio::test]
    async fn test_failure_tracking() {
        let rotator = ProxyRotator::new().with_max_failures(2);
        {
            let mut state = rotator.state.write().await;
            state.proxies = vec![ProxyEntry {
                address: "http://bad-proxy:8080".to_string(),
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            }];
        }

        rotator.record_failure("http://bad-proxy:8080").await;
        {
            let state = rotator.state.read().await;
            assert_eq!(state.proxies[0].consecutive_failures, 1);
            assert_eq!(state.proxies[0].health, ProxyHealth::Degraded);
        }

        rotator.record_failure("http://bad-proxy:8080").await;
        {
            let state = rotator.state.read().await;
            assert_eq!(state.proxies[0].consecutive_failures, 2);
            assert_eq!(state.proxies[0].health, ProxyHealth::Unavailable);
        }

        // After marking unavailable, the proxy should not be returned natively, but acts as last resort since it's the only one.
        assert!(rotator.next().await.is_some());
    }

    #[tokio::test]
    async fn test_success_resets_failures() {
        let rotator = ProxyRotator::new();
        {
            let mut state = rotator.state.write().await;
            state.proxies = vec![ProxyEntry {
                address: "http://proxy:8080".to_string(),
                health: ProxyHealth::Degraded,
                last_checked: None,
                consecutive_failures: 2,
                avg_latency_ms: None,
            }];
        }

        rotator.record_success("http://proxy:8080").await;
        {
            let state = rotator.state.read().await;
            assert_eq!(state.proxies[0].consecutive_failures, 0);
            assert_eq!(state.proxies[0].health, ProxyHealth::Healthy);
        }
    }

    #[tokio::test]
    async fn test_latency_tracking() {
        let rotator = ProxyRotator::new();
        {
            let mut state = rotator.state.write().await;
            state.proxies = vec![ProxyEntry {
                address: "http://proxy:8080".to_string(),
                health: ProxyHealth::Healthy,
                last_checked: None,
                consecutive_failures: 0,
                avg_latency_ms: None,
            }];
        }

        rotator.record_latency("http://proxy:8080", 100).await;
        {
            let state = rotator.state.read().await;
            assert_eq!(state.proxies[0].avg_latency_ms, Some(100));
        }

        // Exponential moving average: 100 * 0.7 + 200 * 0.3 = 70 + 60 = 130
        rotator.record_latency("http://proxy:8080", 200).await;
        {
            let state = rotator.state.read().await;
            assert_eq!(state.proxies[0].avg_latency_ms, Some(130));
        }
    }
}
