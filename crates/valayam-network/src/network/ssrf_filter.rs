use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use valayam_models::error::ScannerError;

/// Configuration for SSRF (Server-Side Request Forgery) protection.
#[derive(Clone, Default)]
pub struct SsrfConfig {
    /// When true, allows requests to private/internal IP ranges.
    pub allow_internal: bool,
}

/// Check whether a URL targets a private/internal IP address.
/// Returns `Ok(())` if the URL is allowed, or `Err(ScannerError::InvalidTarget)`
/// with an SSRF-specific message if the target is a private IP and internal
/// scanning is not enabled.
pub fn reject_private_ip(url_str: &str, config: &SsrfConfig) -> Result<(), ScannerError> {
    if config.allow_internal {
        return Ok(());
    }

    let parsed = match reqwest::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Ok(()), // Can't parse, let downstream handle
    };

    let host = match parsed.host_str() {
        Some(h) => h,
        None => return Ok(()),
    };

    // Check well-known hostnames first
    if host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("localhost.localdomain")
        || host.eq_ignore_ascii_case("metadata.google.internal")
    {
        return Err(ssrf_error(host));
    }

    // Try to parse as IP address
    // Strip surrounding brackets for IPv6 (host_str may include them depending on url crate version/platform)
    let host_trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_trimmed.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(ssrf_error(host));
        }
        return Ok(());
    }

    // For hostnames that aren't IP literals, check dotted-quad patterns
    // that might bypass a hostname check (e.g. "10.0.0.1.nip.io")
    // This is limited — full DNS rebinding protection requires runtime resolution
    if let Ok(ip) = resolve_dotted_host(host) {
        if is_private_ip(&ip) {
            return Err(ssrf_error(host));
        }
    }

    Ok(())
}

fn ssrf_error(host: &str) -> ScannerError {
    ScannerError::InvalidTarget(format!("SSRF: private IP blocked: {}", host))
}

/// Check if an IP address falls in a private or link-local range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    match octets[0] {
        10 => true,                            // 10.0.0.0/8
        127 => true,                           // 127.0.0.0/8 (loopback)
        169 => octets[1] == 254,               // 169.254.0.0/16 (link-local)
        172 => (16..=31).contains(&octets[1]), // 172.16.0.0/12
        192 => octets[1] == 168,               // 192.168.0.0/16
        _ => false,
    }
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    // ::1 (loopback)
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
        && segments[6] == 0
        && segments[7] == 1
    {
        return true;
    }
    // fe80::/10 (link-local)
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // fd00::/8 (unique local)
    if segments[0] & 0xff00 == 0xfd00 {
        return true;
    }
    false
}

/// Extract an IPv4 address from a dotted hostname in the last 4 octets.
/// Handles patterns like `10.0.0.1.nip.io` → `10.0.0.1`.
fn resolve_dotted_host(host: &str) -> Result<IpAddr, ()> {
    // Take the first 1-4 dot-separated segments that look like an IPv4 address
    // from the left. Most SSRF bypass DNS tricks embed IPs at the start.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 4 {
        return Err(());
    }

    // Check if the first 4 segments form a valid IPv4 octet sequence
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().take(4).enumerate() {
        let val: u8 = match part.parse() {
            Ok(v) => v,
            Err(_) => return Err(()),
        };
        octets[i] = val;
    }

    Ok(IpAddr::V4(Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_internal_bypass() {
        let config_block = SsrfConfig::default();
        let config_allow = SsrfConfig {
            allow_internal: true,
        };

        assert!(reject_private_ip("http://127.0.0.1:8080", &config_block).is_err());
        assert!(reject_private_ip("http://127.0.0.1:8080", &config_allow).is_ok());
    }

    #[test]
    fn test_loopback_v4() {
        let config = SsrfConfig::default();
        for ip in &["127.0.0.1", "127.0.0.0", "127.255.255.255"] {
            assert!(
                reject_private_ip(&format!("http://{}:80/path", ip), &config).is_err(),
                "should block loopback: {}",
                ip
            );
        }
    }

    #[test]
    fn test_private_10_range() {
        let config = SsrfConfig::default();
        for ip in &["10.0.0.1", "10.255.255.255", "10.1.2.3"] {
            assert!(
                reject_private_ip(&format!("http://{}/test", ip), &config).is_err(),
                "should block 10.x: {}",
                ip
            );
        }
    }

    #[test]
    fn test_private_172_range() {
        let config = SsrfConfig::default();
        // 172.16.0.0/12 should be blocked
        for ip in &["172.16.0.1", "172.31.255.255", "172.20.1.1"] {
            assert!(
                reject_private_ip(&format!("http://{}", ip), &config).is_err(),
                "should block 172.16-31: {}",
                ip
            );
        }
        // 172.32.0.0 should NOT be blocked (outside 172.16/12)
        assert!(
            reject_private_ip("http://172.32.0.1", &config).is_ok(),
            "should not block 172.32.x"
        );
    }

    #[test]
    fn test_private_192_168() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://192.168.1.1", &config).is_err());
        assert!(reject_private_ip("http://192.168.255.255", &config).is_err());
    }

    #[test]
    fn test_link_local_169() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://169.254.169.254/latest/meta-data/", &config).is_err());
        assert!(reject_private_ip("http://169.254.1.1", &config).is_err());
    }

    #[test]
    fn test_cloud_metadata_hostnames() {
        let config = SsrfConfig::default();
        assert!(
            reject_private_ip("http://metadata.google.internal", &config).is_err(),
            "should block GCP metadata hostname"
        );
    }

    #[test]
    fn test_localhost_hostname() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://localhost:5000/api", &config).is_err());
        assert!(reject_private_ip("http://localhost.localdomain:8080", &config).is_err());
    }

    #[test]
    fn test_ipv6_loopback() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://[::1]:8080/", &config).is_err());
    }

    #[test]
    fn test_ipv6_link_local() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://[fe80::1]/", &config).is_err());
        assert!(reject_private_ip("http://[fe80::dead:beef]/", &config).is_err());
    }

    #[test]
    fn test_ipv6_unique_local() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://[fd00::1]/", &config).is_err());
        assert!(reject_private_ip("http://[fd12:3456::1]/", &config).is_err());
    }

    #[test]
    fn test_public_ip_allowed() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://93.184.216.34", &config).is_ok());
        assert!(reject_private_ip("http://8.8.8.8", &config).is_ok());
        assert!(reject_private_ip("https://example.com", &config).is_ok());
    }

    #[test]
    fn test_public_ipv6_allowed() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("http://[2001:4860:4860::8888]", &config).is_ok());
    }

    #[test]
    fn test_invalid_url_does_not_panic() {
        let config = SsrfConfig::default();
        assert!(reject_private_ip("not a url", &config).is_ok());
        assert!(reject_private_ip("", &config).is_ok());
    }

    #[test]
    fn test_dotted_host_detection() {
        let config = SsrfConfig::default();
        // 10.0.0.1.nip.io — embedded private IP in hostname
        assert!(
            reject_private_ip("http://10.0.0.1.nip.io", &config).is_err(),
            "should detect embedded private IP in hostname"
        );
    }

    #[test]
    fn test_dotted_host_public_allowed() {
        let config = SsrfConfig::default();
        // The first 4 octets are NOT a valid IP
        assert!(
            reject_private_ip("http://example.com", &config).is_ok(),
            "regular hostname should pass"
        );
    }

    #[test]
    fn test_is_private_v4() {
        assert!(is_private_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_v4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_v4(&Ipv4Addr::new(169, 254, 169, 254)));
        assert!(is_private_v4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_v4(&Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_v4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_private_v4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_v4(&Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn test_resolve_dotted_host() {
        assert_eq!(
            resolve_dotted_host("10.0.0.1.nip.io").unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert!(resolve_dotted_host("example.com").is_err());
        assert!(resolve_dotted_host("1.2.3").is_err());
    }
}
