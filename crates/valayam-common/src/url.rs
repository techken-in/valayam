use url::Url;

/// Extracts the host from a target string.
/// If the string is a valid URL, it returns the host component.
/// If the string is not a valid URL (e.g. an IP address or raw hostname), it returns the original string.
pub fn extract_host(target: &str) -> String {
    match Url::parse(target) {
        Ok(u) => u.host_str().unwrap_or(target).to_string(),
        Err(_) => target.to_string(),
    }
}
