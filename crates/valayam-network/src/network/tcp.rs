use futures::future::join_all;
use std::collections::HashSet;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result of a TCP port scan, including optional banner data.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub banner: Option<String>,
    /// Additional metadata about the service
    pub service_info: ServiceInfo,
}

/// Additional service information discovered during scanning
#[derive(Debug, Clone, Default)]
pub struct ServiceInfo {
    /// Detected service name (HTTP, SSH, MySQL, etc.)
    pub service_name: Option<String>,
    /// Detected service version if available
    pub version: Option<String>,
    /// Product information from banner
    pub product: Option<String>,
    /// Operating system hints from banner
    pub os_hint: Option<String>,
    /// Whether this appears to be a web service
    pub is_web_service: bool,
    /// Available HTTP methods if web service
    pub http_methods: Vec<String>,
    /// TLS/SSL information if applicable
    pub tls_info: Option<TlsInfo>,
}

/// TLS/SSL information for a service
#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    /// TLS version negotiated
    pub version: Option<String>,
    /// Cipher suite used
    pub cipher_suite: Option<String>,
    /// Certificate information (simplified)
    pub cert_info: Option<String>,
    /// Whether the certificate is self-signed
    pub is_self_signed: bool,
    /// Whether the certificate is trusted
    pub is_trusted: bool,
}

/// Parses a list of port strings, expanding ranges into individual port numbers.
/// E.g., ["80", "443", "8000-8080"] -> {80, 443, 8000, 8001, ..., 8080}
fn parse_ports(ports: &[String]) -> Result<HashSet<u16>, String> {
    let mut parsed_ports = HashSet::new();
    for port_str in ports {
        if let Some((start, end)) = port_str.split_once('-') {
            let start_port: u16 = start
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range start: {}", start))?;
            let end_port: u16 = end
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range end: {}", end))?;
            if start_port > end_port {
                return Err(format!(
                    "Invalid port range: start > end ({} > {})",
                    start_port, end_port
                ));
            }
            for port in start_port..=end_port {
                parsed_ports.insert(port);
            }
        } else {
            let port: u16 = port_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {}", port_str))?;
            parsed_ports.insert(port);
        }
    }
    Ok(parsed_ports)
}

/// Advanced service detection based on banner analysis
fn detect_service_from_banner(port: u16, banner: &str) -> ServiceInfo {
    let mut info = ServiceInfo::default();
    let _banner_lower = banner.to_lowercase();

    // HTTP/S detection
    if banner.contains("HTTP") || banner.contains("html") || banner.contains("<!doctype") {
        info.is_web_service = true;
        info.service_name = Some("HTTP".to_string());

        // Try to extract server header
        if let Some(server_line) = banner
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
        {
            info.product = Some(server_line["server:".len()..].trim().to_string());
        }

        // Check for HTTPS indicators
        if banner.contains("HTTPS") || banner.contains("TLS") || banner.contains("SSL") {
            info.tls_info = Some(TlsInfo {
                is_trusted: false, // Would need actual TLS check
                ..Default::default()
            });
        }
    }
    // SSH detection
    else if banner.starts_with("SSH-") || banner.contains("OpenSSH") {
        info.service_name = Some("SSH".to_string());
        if let Some(version) = extract_version_from_ssh_banner(banner) {
            info.version = Some(version);
        }
        if banner.contains("OpenSSH") {
            info.product = Some("OpenSSH".to_string());
        }
    }
    // FTP detection
    else if banner.contains("FTP") || banner.contains("File Transfer Protocol") {
        info.service_name = Some("FTP".to_string());
        // Extract version if possible
        if let Some(version) = extract_version_from_ftp_banner(banner) {
            info.version = Some(version);
        }
    }
    // SMTP detection
    else if banner.contains("SMTP") || banner.contains("Simple Mail Transfer") {
        info.service_name = Some("SMTP".to_string());
        if banner.contains("ESMTP") {
            // ESMTP indicates extended capabilities
        }
        if let Some(version) = extract_version_from_smtp_banner(banner) {
            info.version = Some(version);
        }
    }
    // MySQL detection
    else if banner.contains("MySQL") {
        info.service_name = Some("MySQL".to_string());
        if let Some(version) = extract_mysql_version(banner) {
            info.version = Some(version);
        }
        info.product = Some("MySQL".to_string());
    }
    // PostgreSQL detection
    else if banner.contains("PostgreSQL") || banner.contains("Postgres") {
        info.service_name = Some("PostgreSQL".to_string());
        if let Some(version) = extract_postgres_version(banner) {
            info.version = Some(version);
        }
        info.product = Some("PostgreSQL".to_string());
    }
    // Microsoft SQL Server detection
    else if banner.contains("Microsoft SQL Server") || banner.contains("MSSQL") {
        info.service_name = Some("MSSQL".to_string());
        if let Some(version) = extract_mssql_version(banner) {
            info.version = Some(version);
        }
        info.product = Some("Microsoft SQL Server".to_string());
    }
    // Redis detection
    else if banner.contains("Redis") {
        info.service_name = Some("Redis".to_string());
        if let Some(version) = extract_redis_version(banner) {
            info.version = Some(version);
        }
        info.product = Some("Redis".to_string());
    }
    // MongoDB detection
    else if banner.contains("MongoDB") {
        info.service_name = Some("MongoDB".to_string());
        if let Some(version) = extract_mongo_version(banner) {
            info.version = Some(version);
        }
        info.product = Some("MongoDB".to_string());
    }
    // Generic fallback - try to extract any version-like string
    else {
        // Try to extract a generic version
        if let Some(version) = extract_generic_version(banner) {
            info.version = Some(version);
        }

        // Try to identify common service names from well-known ports
        info.service_name = match port {
            21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            143 => Some("IMAP".to_string()),
            443 => Some("HTTPS".to_string()),
            993 => Some("IMAPS".to_string()),
            995 => Some("POP3S".to_string()),
            3306 => Some("MySQL".to_string()),
            3389 => Some("RDP".to_string()),
            5432 => Some("PostgreSQL".to_string()),
            5900 => Some("VNC".to_string()),
            6379 => Some("Redis".to_string()),
            8080 => Some("HTTP-Proxy".to_string()),
            8443 => Some("HTTPS-Alt".to_string()),
            27017 => Some("MongoDB".to_string()),
            _ => None,
        };
    }

    info
}

/// Extract version from SSH banner (e.g., "SSH-2.0-OpenSSH_7.4")
fn extract_version_from_ssh_banner(banner: &str) -> Option<String> {
    // SSH-2.0-OpenSSH_7.4p1 Ubuntu-10
    let re = regex::Regex::new(r"SSH-\d+\.\d+-([^ \r\n]+)").ok()?;
    re.captures(banner)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

/// Extract version from FTP banner
fn extract_version_from_ftp_banner(banner: &str) -> Option<String> {
    // Examples: "220 vsFTPd 3.0.5", "220 Microsoft FTP Service"
    let re = regex::Regex::new(r"(?i)v[0-9]+\.[0-9]+\.[0-9]+|\d+\.\d+\.\d+").ok()?;
    re.find(banner).map(|m| {
        let ver = m.as_str();
        ver.strip_prefix('v').unwrap_or(ver).to_string()
    })
}

/// Extract version from SMTP banner
fn extract_version_from_smtp_banner(banner: &str) -> Option<String> {
    // Examples: "220 mail.example.com ESMTP Postfix", "220 Microsoft ESMTP MAIL Service"
    let _re = regex::Regex::new(
        r"(?i)(?:esmtp|smtp).*?([0-9]+\.[0-9]+\.[0-9]+)|([0-9]+\.[0-9]+\.[0-9]+)\s*(?:esmtp|smtp)",
    )
    .ok()?;
    // Simplified extraction
    let re_simple = regex::Regex::new(r"\d+\.\d+\.\d+").ok()?;
    re_simple.find(banner).map(|m| m.as_str().to_string())
}

/// Extract MySQL version from initial packet
fn extract_mysql_version(banner: &str) -> Option<String> {
    // MySQL sends a greeting packet in binary format
    // This is simplified - real implementation would parse the binary packet
    if banner.contains("mysql") {
        // Try to extract version from printable parts
        let re = regex::Regex::new(r"\d+\.\d+\.\d+").ok()?;
        return re.find(banner).map(|m| m.as_str().to_string());
    }
    None
}

/// Extract PostgreSQL version
fn extract_postgres_version(banner: &str) -> Option<String> {
    // Look for PostgreSQL semantic versions in the banner string
    let re = regex::Regex::new(r"(?i)PostgreSQL\s+(\d+\.\d+(\.\d+)?)").ok()?;
    re.captures(banner)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract MSSQL version
fn extract_mssql_version(banner: &str) -> Option<String> {
    // Look for Microsoft SQL Server versions
    let re = regex::Regex::new(r"(?i)Microsoft SQL Server.*?(\d+\.\d+\.\d+(\.\d+)?)").ok()?;
    re.captures(banner)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract Redis version
fn extract_redis_version(banner: &str) -> Option<String> {
    // Redis typically sends something like "redis_version:6.2.6\r\n"
    let re = regex::Regex::new(r"redis_version:?(\d+\.\d+\.\d+)").ok()?;
    re.find(banner).map(|m| {
        m.as_str()
            .split(':')
            .nth(1)
            .unwrap_or(m.as_str())
            .to_string()
    })
}

/// Extract MongoDB version
fn extract_mongo_version(banner: &str) -> Option<String> {
    // Look for MongoDB versions
    let re = regex::Regex::new(r"(?i)MongoDB.*?(\d+\.\d+\.\d+(\.\d+)?)").ok()?;
    re.captures(banner)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Generic version extractor for unknown services
fn extract_generic_version(banner: &str) -> Option<String> {
    // Look for common version patterns
    let patterns = [
        regex::Regex::new(r"\d+\.\d+\.\d+").ok(),
        regex::Regex::new(r"v\d+\.\d+\.\d+").ok(),
        regex::Regex::new(r"version\s+\d+\.\d+\.\d+").ok(),
    ];

    for pattern in patterns.iter().flatten() {
        if let Some(m) = pattern.find(banner) {
            return Some(m.as_str().to_string());
        }
    }

    None
}

/// Performs an enhanced TCP connect scan on a list of ports for a given host.
/// Returns a vector of `PortResult` for ports that were found to be open.
///
/// Enhancements over basic version:
/// - Improved banner grabbing with multiple strategies
/// - Service detection and version extraction
/// - Better timeout handling
/// - HTTP-specific probing for web services
pub async fn scan_ports(
    host: &str,
    ports: &[String],
    banner_timeout_ms: Option<u64>,
    enable_service_detection: bool,
    send_probe: Option<String>,
    stealth_syn_scan: bool,
) -> Vec<PortResult> {
    let Ok(parsed_ports) = parse_ports(ports) else {
        eprintln!("[!] Invalid port format provided.");
        return Vec::new();
    };

    let send_probe_arc = std::sync::Arc::new(send_probe);

    let scan_futures = parsed_ports.into_iter().map(|port| {
        let host = host.to_string();
        let banner_ms = banner_timeout_ms;
        let _detect_service = enable_service_detection;
        let probe = send_probe_arc.clone();

        tokio::spawn(async move {
            let address = format!("{}:{}", host, port);
            let connect_timeout = Duration::from_secs(3); // Slightly increased for reliability

            // If stealth SYN scan is enabled, attempt it first
            if stealth_syn_scan {
                if let Ok(target_ip) = host.parse::<std::net::IpAddr>() {
                    // Try the raw SYN scan. If it fails due to permissions (or any error), fall back to standard connect
                    match crate::network::raw::syn_scan(target_ip, port, connect_timeout).await {
                        Ok(true) => {
                            // Port is open according to SYN-ACK
                            // We can't easily grab banners passively from a raw SYN-ACK without completing the handshake.
                            // We return basic information.
                            return Some(PortResult {
                                port,
                                banner: None,
                                service_info: ServiceInfo {
                                    service_name: Some("unknown".to_string()),
                                    ..Default::default()
                                },
                            });
                        }
                        Ok(false) => {
                            // Port is closed or filtered
                            return None;
                        }
                        Err(_) => {
                            // Permission error or raw socket failure; fallback to connect scan below
                            tracing::debug!(
                                "Raw SYN scan failed for {}, falling back to Connect scan",
                                address
                            );
                        }
                    }
                }
            }

            // Attempt TCP Connect connection
            let mut stream = match timeout(connect_timeout, TcpStream::connect(&address)).await {
                Ok(Ok(s)) => s,
                _ => return None, // Connection failed or timed out
            };

            // Get peer address for logging/tracing
            let _peer_addr = stream.peer_addr().ok();

            // Optional: send custom probe before reading
            if let Some(ref probe_data) = *probe {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(probe_data.as_bytes()).await;
            }

            // Phase 1: Passive banner grabbing
            let mut banner = if let Some(ms) = banner_ms {
                let banner_timeout = Duration::from_millis(ms);
                let mut buf = vec![0u8; 4096]; // Increased buffer size
                match timeout(banner_timeout, stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let banner_text = match String::from_utf8_lossy(&buf[..n]) {
                            std::borrow::Cow::Owned(s) => s,
                            std::borrow::Cow::Borrowed(s) => s.to_string(),
                        };
                        Some(banner_text.trim().to_string())
                    }
                    _ => None,
                }
            } else {
                None
            };

            // Phase 2: Active probing if no banner received and timeout was specified
            let mut service_info = ServiceInfo::default();
            if banner.is_none() && banner_ms.is_some() {
                // Try to elicit a response with protocol-specific probes
                if let Some(probe_banner) = probe_service(&mut stream, port).await {
                    banner = Some(probe_banner);
                }
            }

            // Phase 3: Service detection if enabled
            if let (Some(banner_text), true) = (banner.as_ref(), enable_service_detection) {
                service_info = detect_service_from_banner(port, banner_text);

                // Additional HTTP-specific checks
                if service_info.is_web_service {
                    // Try to get more details via HTTP OPTIONS or GET
                    if let Some(http_info) = probe_http_service(&mut stream).await {
                        service_info.http_methods = http_info.methods;
                        if let Some(server) = http_info.server {
                            if service_info.product.is_none() {
                                service_info.product = Some(server);
                            }
                        }
                    }
                }
            }

            // Build final result
            Some(PortResult {
                port,
                banner,
                service_info,
            })
        })
    });

    let results = join_all(scan_futures).await;

    results
        .into_iter()
        .filter_map(|res| res.unwrap_or(None))
        .collect()
}

/// Probe a service with protocol-specific requests to elicit a banner
async fn probe_service(stream: &mut TcpStream, port: u16) -> Option<String> {
    // Try common probes based on port
    match port {
        // Web servers - try GET request
        80 | 443 | 8080 | 8443 | 8000 | 8001 | 8888 => probe_http_get(stream).await,
        // SSH - usually sends banner immediately, but we can try to interact
        22 => None, // SSH typically sends banner on connect
        // FTP - usually sends banner immediately
        21 => None,
        // SMTP - usually sends banner immediately
        25 => None,
        // DNS - not really applicable for TCP probe
        53 => None,
        // Database ports - try to elicit response
        3306 | 5432 | 1433 | 6379 | 27017 => {
            // For most DBs, we'd need to send proper protocol packets
            // This is simplified - in reality would need protocol-specific probes
            None
        }
        _ => None, // No specific probe for other ports
    }
}

/// Perform an HTTP GET request to try to get more detailed banner
async fn probe_http_get(stream: &mut TcpStream) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Simple HTTP GET request
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    if stream.write_all(request).await.is_err() {
        return None;
    }

    // Set a short timeout for the response
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);
            // Extract Server header if present
            if let Some(server_line) = response
                .lines()
                .find(|line| line.to_lowercase().starts_with("server:"))
            {
                return Some(server_line["server:".len()..].trim().to_string());
            }
            // Return first line of response as fallback
            if let Some(first_line) = response.lines().next() {
                return Some(first_line.trim().to_string());
            }
            None
        }
        _ => None,
    }
}

/// Extract HTTP-specific information from a connection
async fn probe_http_service(stream: &mut TcpStream) -> Option<HttpServiceInfo> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Try OPTIONS request to see what methods are allowed
    let options_request = b"OPTIONS / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    if stream.write_all(options_request).await.is_err() {
        return None;
    }

    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);
            let mut methods = Vec::new();
            let mut server = None;

            // Parse Allow header
            if let Some(allow_line) = response
                .lines()
                .find(|line| line.to_lowercase().starts_with("allow:"))
            {
                let methods_str = &allow_line["allow:".len()..];
                for method in methods_str.split(',') {
                    let method = method.trim().to_uppercase();
                    if !method.is_empty() {
                        methods.push(method);
                    }
                }
            }

            // Parse Server header
            if let Some(server_line) = response
                .lines()
                .find(|line| line.to_lowercase().starts_with("server:"))
            {
                server = Some(server_line["server:".len()..].trim().to_string());
            }

            Some(HttpServiceInfo { methods, server })
        }
        _ => None,
    }
}

/// Information gathered from HTTP service probing
#[derive(Debug, Clone, Default)]
struct HttpServiceInfo {
    /// HTTP methods supported (from Allow header)
    pub methods: Vec<String>,
    /// Server header value
    pub server: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_ports() {
        let ports = vec!["80".to_string(), "443".to_string(), "8000-8010".to_string()];
        let result = parse_ports(&ports).expect("Should parse ports");
        assert!(result.contains(&80));
        assert!(result.contains(&443));
        assert!(result.contains(&8000));
        assert!(result.contains(&8005));
        assert!(result.contains(&8010));
        assert!(!result.contains(&8011)); // Out of range
    }

    #[tokio::test]
    async fn test_detect_service_from_banner() {
        // Test HTTP detection
        let info = detect_service_from_banner(80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n");
        assert!(info.is_web_service);
        assert_eq!(info.service_name.as_deref(), Some("HTTP"));
        assert_eq!(info.product.as_deref(), Some("Apache/2.4.41"));

        // Test SSH detection
        let info = detect_service_from_banner(22, "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10");
        assert_eq!(info.service_name.as_deref(), Some("SSH"));
        assert_eq!(info.version.as_deref(), Some("OpenSSH_7.4p1"));
        assert_eq!(info.product.as_deref(), Some("OpenSSH"));

        // Test MySQL detection
        let _info =
            detect_service_from_banner(3306, "\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x33");
        // Note: This is a simplified test - real MySQL packet parsing would be more complex
    }

    #[tokio::test]
    async fn test_extract_version_from_ssh_banner() {
        let version = extract_version_from_ssh_banner("SSH-2.0-OpenSSH_7.4p1 Ubuntu-10ubuntu1")
            .expect("Should extract version");
        assert_eq!(version, "OpenSSH_7.4p1");

        let version = extract_version_from_ssh_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
            .expect("Should extract version");
        assert_eq!(version, "OpenSSH_8.9p1");
    }
}
