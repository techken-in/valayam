use parking_lot::Mutex;
use rand::{distributions::Alphanumeric, Rng};
use std::collections::HashSet;

/// Correlation engine for generating short-lived OOB IDs.
pub struct CorrelationEngine;

static GENERATED_IDS: std::sync::LazyLock<Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

impl CorrelationEngine {
    /// Generates a random alphanumeric correlation ID of length 12.
    pub fn generate_id() -> String {
        let mut id;
        loop {
            let rng = rand::thread_rng();
            id = rng
                .sample_iter(&Alphanumeric)
                .take(12)
                .map(char::from)
                .collect::<String>()
                .to_lowercase();
            let mut seen = GENERATED_IDS.lock();
            if seen.insert(id.clone()) {
                break;
            }
        }
        id
    }

    /// Generate a timestamp-prefixed correlation ID for ordering.
    pub fn generate_timestamped_id() -> String {
        let ts = chrono::Utc::now().timestamp_millis();
        let rng = rand::thread_rng();
        let random_part: String = rng
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        format!("{:x}{}", ts, random_part).to_lowercase()
    }

    /// Formats the correlation ID into a full hostname, e.g., `abc123yz.valayam.local`.
    pub fn format_domain(id: &str, base_domain: &str) -> String {
        format!("{}.{}", id, base_domain)
    }

    /// Format callback URL for injection into payloads.
    pub fn callback_url(id: &str, base_domain: &str) -> String {
        format!("http://{}.{}/{}", id, base_domain, id)
    }

    /// Format DNS callback domain for injection.
    pub fn dns_domain(id: &str, base_domain: &str) -> String {
        format!("{}.{}", id, base_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_unique() {
        let id1 = CorrelationEngine::generate_id();
        let id2 = CorrelationEngine::generate_id();
        assert_eq!(id1.len(), 12);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_generate_timestamped_id() {
        let id = CorrelationEngine::generate_timestamped_id();
        assert!(id.len() >= 12);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_format_domain() {
        let domain = CorrelationEngine::format_domain("abc123", "oob.valayam.local");
        assert_eq!(domain, "abc123.oob.valayam.local");
    }

    #[test]
    fn test_callback_url() {
        let url = CorrelationEngine::callback_url("abc123", "oob.valayam.local");
        assert_eq!(url, "http://abc123.oob.valayam.local/abc123");
    }
}
