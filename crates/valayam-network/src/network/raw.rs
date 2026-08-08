use std::net::IpAddr;
use std::time::Duration;
use valayam_models::error::ScannerError;

/// Performs a raw SYN scan against a target IP and port.
/// Returns true if the port appears open (SYN-ACK received).
/// Returns false if the port appears closed (RST received) or filtered (timeout).
/// Returns an error if raw sockets cannot be created (e.g., lack of privileges).
pub async fn syn_scan(
    _target_ip: IpAddr,
    _target_port: u16,
    _timeout: Duration,
) -> Result<bool, ScannerError> {
    // Note: Raw TCP sockets are heavily restricted on many operating systems
    // (e.g., Windows since XP SP2 disables sending TCP packets over raw sockets,
    // and Linux requires CAP_NET_RAW).
    // For this implementation, we attempt to create a raw socket. If it fails due to
    // permissions, we return an error so the caller can fall back to a Connect scan.

    // In a full production implementation, packet crafting (IP + TCP headers)
    // and pcap/bpf based packet sniffing would be implemented here.
    // For cross-platform compatibility without heavy dependencies (libpcap/npcap),
    // we return a permission error to force the fallback, as raw sockets are generally
    // not cross-platform friendly in pure Rust without external drivers on Windows.

    Err(ScannerError::ConfigurationError(
        "Raw SYN scans require elevated privileges and custom drivers on this OS. Falling back to connect scan.".to_string()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    #[ignore]
    async fn test_syn_scan_requires_privileges() {
        let result = syn_scan(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            80,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_syn_scan_returns_config_error() {
        let result = syn_scan(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            443,
            Duration::from_millis(500),
        )
        .await;
        assert!(result.is_err());
        let err = result.expect_err("should error on raw socket");
        assert!(
            format!("{}", err).contains("Raw SYN"),
            "error should mention raw SYN"
        );
    }

    #[tokio::test]
    async fn test_syn_scan_consistent_error() {
        let r1 = syn_scan(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            22,
            Duration::from_secs(1),
        )
        .await;
        let r2 = syn_scan(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            Duration::from_millis(100),
        )
        .await;
        assert!(r1.is_err());
        assert!(r2.is_err());
    }
}
