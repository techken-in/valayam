// WASM-only: host function bindings supplied by the Extism runtime.
// Non-WASM builds (e.g. Windows test/dev) use stub implementations.

#[cfg(target_arch = "wasm32")]
#[extism_pdk::host_fn]
extern "ExtismHost" {
    pub fn dns_resolve(domain: String) -> String;
    pub fn kv_get(key: String) -> String;
    pub fn kv_set(input: String) -> String;
}

#[cfg(not(target_arch = "wasm32"))]
pub mod _stubs {
    use std::net::ToSocketAddrs;
    pub fn dns_resolve(domain: String) -> String {
        let result: Vec<String> = (domain.as_str(), 0)
            .to_socket_addrs()
            .ok()
            .into_iter()
            .flatten()
            .map(|a| a.ip().to_string())
            .collect();
        serde_json::to_string(&result).unwrap_or_else(|_| "[]".into())
    }
}

#[cfg(target_arch = "wasm32")]
fn dns_resolve_fallback(domain: &str) -> Option<Vec<String>> {
    let res = unsafe { dns_resolve(domain.to_string()) };
    if let Ok(json) = res {
        if let Ok(ips) = serde_json::from_str::<Vec<String>>(&json) {
            return Some(ips);
        }
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
fn dns_resolve_fallback(domain: &str) -> Option<Vec<String>> {
    let json = _stubs::dns_resolve(domain.to_string());
    serde_json::from_str::<Vec<String>>(&json)
        .ok()
        .filter(|v| !v.is_empty())
}

pub fn resolve_dns(domain: &str) -> Option<Vec<String>> {
    dns_resolve_fallback(domain)
}

#[cfg(target_arch = "wasm32")]
fn kv_get_fallback(key: &str) -> Option<String> {
    let res = unsafe { kv_get(key.to_string()) };
    if let Ok(content) = res {
        if !content.is_empty() {
            return Some(content);
        }
    }
    None
}

#[cfg(not(target_arch = "wasm32"))]
lazy_static::lazy_static! {
    static ref KV_STORE: std::sync::Mutex<std::collections::HashMap<String, String>> = std::sync::Mutex::new(std::collections::HashMap::new());
}

#[cfg(not(target_arch = "wasm32"))]
fn kv_get_fallback(key: &str) -> Option<String> {
    if let Ok(store) = KV_STORE.lock() {
        store.get(key).cloned()
    } else {
        None
    }
}

pub fn get_state(key: &str) -> Option<String> {
    kv_get_fallback(key)
}

#[cfg(target_arch = "wasm32")]
fn kv_set_fallback(key: &str, value: &str) -> bool {
    let json = format!(r#"{{"key":"{}","value":"{}"}}"#, key, value);
    let res = unsafe { kv_set(json) };
    if let Ok(status) = res {
        return status == "ok";
    }
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn kv_set_fallback(key: &str, value: &str) -> bool {
    if let Ok(mut store) = KV_STORE.lock() {
        store.insert(key.to_string(), value.to_string());
        true
    } else {
        false
    }
}

pub fn set_state(key: &str, value: &str) -> bool {
    kv_set_fallback(key, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_dns_returns_some_for_loopback() {
        let result = resolve_dns("127.0.0.1");
        assert!(result.is_some(), "127.0.0.1 should resolve");
    }

    #[test]
    fn test_get_state_returns_none_for_missing() {
        let result = get_state("nonexistent_key");
        assert!(result.is_none());
    }

    #[test]
    fn test_set_state_returns_true_in_stub() {
        let result = set_state("key", "value");
        assert!(result, "host stub should return true after setting");
        assert_eq!(get_state("key"), Some("value".to_string()));
    }

    #[test]
    fn test_resolve_dns_returns_some_for_localhost() {
        let result = resolve_dns("localhost");
        assert!(result.is_some(), "localhost should resolve");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_stub_dns_resolve_valid_domain() {
        let json = _stubs::dns_resolve("127.0.0.1".to_string());
        let ips: Vec<String> = serde_json::from_str(&json).expect("valid JSON array");
        assert!(!ips.is_empty(), "127.0.0.1 should have at least one IP");
        assert!(ips.contains(&"127.0.0.1".to_string()));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_stub_dns_resolve_invalid_domain() {
        let json = _stubs::dns_resolve("invalid-domain-that-does-not-exist--.com".to_string());
        let ips: Vec<String> = serde_json::from_str(&json).expect("valid JSON array");
        assert!(
            ips.is_empty(),
            "non-existent domain should return empty array"
        );
    }
}
