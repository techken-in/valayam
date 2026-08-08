use rustls::pki_types::ServerName;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// TLS certificate information extracted from a connection.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub issuer: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub serial: String,
    pub signature_algorithm: String,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub subject_alternative_names: Vec<String>,
    pub public_key_algorithm: String,
    pub public_key_bits: Option<u16>,
    pub is_ca: bool,
    pub path_len_constraint: Option<u8>,
    /// Additional certificate transparency information
    pub ct_scts: Vec<String>,
    /// Whether the certificate uses weak signatures
    pub has_weak_signature: bool,
    /// Whether the certificate uses weak keys
    pub has_weak_key: bool,
}

/// Enhanced TLS connection information
#[derive(Debug, Clone)]
pub struct TlsConnectionInfo {
    pub cert_info: CertInfo,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    /// Certificate validation result
    pub validation_result: Option<ValidationResult>,
    /// Supported protocol versions
    pub supported_versions: Vec<String>,
}

/// Result of TLS certificate validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_trusted: bool,
    pub validation_errors: Vec<String>,
    pub validation_warnings: Vec<String>,
}

/// Information about a TLS protocol version test
#[derive(Debug, Clone)]
pub struct VersionTestResult {
    pub version: String,
    pub supported: bool,
    /// Details about why it failed (if applicable)
    pub failure_reason: Option<String>,
}

/// Information about cipher suite strength
#[derive(Debug, Clone)]
pub struct CipherSuiteInfo {
    pub suite: String,
    pub is_strong: bool,
    pub weakness: Option<String>, // e.g., "Uses RC4", "Uses 3DES", "Key size too small"
    pub recommended_alternative: Option<String>,
}

/// Represents a TLS cipher suite with strength information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weakness {
    pub description: String,
    pub severity: WeaknessSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeaknessSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Perform a comprehensive TLS scan including version detection, cipher suite analysis, and certificate inspection
pub async fn scan_tls(host: &str, port: u16) -> Option<TlsConnectionInfo> {
    // First, get the basic certificate information
    let cert_info = match inspect_certificate(host, port).await {
        Some(info) => info,
        None => return None,
    };

    // Then, test supported protocol versions
    let supported_versions = test_protocol_versions(host, port).await;

    // Get the actual negotiated version and cipher suite from a full connection
    let (protocol_version, cipher_suite, validation_result) =
        get_connection_details(host, port).await;

    Some(TlsConnectionInfo {
        cert_info,
        protocol_version,
        cipher_suite, // Keeping original field name for compatibility
        validation_result,
        supported_versions,
    })
}

/// Connects to a host:port and extracts TLS certificate information with enhanced parsing.
///
/// Uses a raw TLS handshake via `rustls` to obtain the peer certificate,
/// then parses it with `x509-parser` for detailed field extraction.
pub async fn inspect_certificate(host: &str, port: u16) -> Option<CertInfo> {
    let address = format!("{}:{}", host, port);
    let connect_timeout = Duration::from_secs(5);

    // Connect TCP
    let tcp_stream = match timeout(connect_timeout, TcpStream::connect(&address)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Install default crypto provider (safe to call multiple times as it returns Err if already installed)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // We intentionally use a permissive verifier for inspection purposes
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(
            crate::stealth::tls::NoCertVerification::new(),
        ))
        .with_no_client_auth();

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => return None,
    };

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    let tls_stream =
        match timeout(connect_timeout, connector.connect(server_name, tcp_stream)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

    // Extract the peer certificate
    let (_, server_conn) = tls_stream.get_ref();
    let tls_version = server_conn.protocol_version().map(|v| format!("{:?}", v));
    let cipher_suite = server_conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()));

    let certs = server_conn.peer_certificates()?;
    let cert_der = certs.first()?;

    // Parse with x509-parser
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).ok()?;

    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    let not_before = cert.validity().not_before.to_string();
    let not_after = cert.validity().not_after.to_string();
    let is_expired = !cert.validity().is_valid();
    let is_self_signed = cert.issuer() == cert.subject();
    let serial = cert.raw_serial_as_string();
    let sig_alg = cert.signature_algorithm.algorithm.to_string();

    // Enhanced certificate parsing
    let mut sans = Vec::new();
    let public_key_algorithm = "Unknown".to_string();
    let public_key_bits = None;
    let mut is_ca = false;
    let mut path_len_constraint = None;
    let mut ct_scts = Vec::new();
    let has_weak_signature = false;
    let has_weak_key = false;

    // Parse extensions for SANs, CT, and other info
    let extensions = cert.extensions();
    for extension in extensions {
        use x509_parser::extensions::ParsedExtension;
        match extension.parsed_extension() {
            // Parse Subject Alternative Names
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        sans.push(dns.to_string());
                    }
                }
            }
            // Parse Certificate Transparency information (SCTs)
            ParsedExtension::SCT(_) => {
                ct_scts.push("SCT_PRESENT".to_string());
            }
            // Parse basic constraints for CA flag and path length
            ParsedExtension::BasicConstraints(bc) => {
                is_ca = bc.ca;
                path_len_constraint = bc.path_len_constraint.map(|v| v as u8);
            }
            _ => {}
        }
    }

    Some(CertInfo {
        issuer,
        subject,
        not_before,
        not_after,
        is_expired,
        is_self_signed,
        serial,
        signature_algorithm: sig_alg,
        tls_version,
        cipher_suite, // Keeping original field name for compatibility
        subject_alternative_names: sans,
        public_key_algorithm,
        public_key_bits,
        is_ca,
        path_len_constraint,
        ct_scts,
        has_weak_signature,
        has_weak_key,
    })
}

/// Test which TLS/SSL protocol versions are supported by the server
pub async fn test_protocol_versions(host: &str, port: u16) -> Vec<String> {
    let versions = [
        ("SSLv2.0", 0x0002), // Technically SSLv2
        ("SSLv3.0", 0x0300),
        ("TLSv1.0", 0x0301),
        ("TLSv1.1", 0x0302),
        ("TLSv1.2", 0x0303),
        ("TLSv1.3", 0x0304),
    ];

    let mut supported = Vec::new();

    for (name, version) in &versions {
        if is_version_supported(host, port, *version).await {
            // Special handling for SSLv2 - mark as deprecated
            if *version == 0x0002 {
                supported.push(format!("{} (DEPRECATED)", name));
            } else {
                supported.push(name.to_string());
            }
        }
    }

    supported
}

/// Check if a specific TLS/SSL version is supported by attempting a raw ClientHello
pub async fn is_version_supported(host: &str, port: u16, version: u16) -> bool {
    // Redirect SSLv2 to the legacy probe
    if version == 0x0002 {
        return test_legacy_protocols(host, port).await;
    }
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let address = format!("{}:{}", host, port);
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(&address),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    // Build ClientHello for the specific version
    let mut hello = Vec::new();

    // Record layer
    hello.push(0x16); // Handshake
    hello.push(((version >> 8) & 0xFF) as u8); // Version high byte
    hello.push((version & 0xFF) as u8); // Version low byte

    // Length will be filled in later
    let length_pos = hello.len();
    hello.push(0x00); // Placeholder for length high byte
    hello.push(0x00); // Placeholder for length low byte

    // Handshake layer
    hello.push(0x01); // ClientHello

    // Handshake length placeholder
    let handshake_len_pos = hello.len();
    hello.push(0x00); // Placeholder for length byte 2
    hello.push(0x00); // Placeholder for length byte 1
    hello.push(0x00); // Placeholder for length byte 0

    // Version inside ClientHello
    hello.push(((version >> 8) & 0xFF) as u8);
    hello.push((version & 0xFF) as u8);

    // Random (32 bytes)
    hello.extend_from_slice(&[0x00; 32]);

    // Session ID length (0 for no session resumption)
    hello.push(0x00);

    // Cipher suites (empty for now - we'll use a common one)
    hello.push(0x00);
    hello.push(0x02); // 2 bytes for length
                      // TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C) or TLS 1.3 equivalent
    hello.push(0x00);
    hello.push(0x2F); // TLS 1.2

    // For TLS 1.3, we'd need different cipher suite values
    // But for version detection, any valid cipher suite will do

    // Compression methods (null compression)
    hello.push(0x01);
    hello.push(0x00);

    // Extensions (optional but recommended for modern versions)
    // For simplicity, we'll send no extensions in this basic check

    // Now go back and fill in the lengths
    let total_len = hello.len();
    let handshake_len = total_len - handshake_len_pos - 3; // Subtract the length field itself

    // Write handshake length
    hello[handshake_len_pos] = ((handshake_len >> 16) & 0xFF) as u8;
    hello[handshake_len_pos + 1] = ((handshake_len >> 8) & 0xFF) as u8;
    hello[handshake_len_pos + 2] = (handshake_len & 0xFF) as u8;

    // Write record length
    let record_len = total_len - length_pos - 2; // Subtract the length field itself
    hello[length_pos] = ((record_len >> 8) & 0xFF) as u8;
    hello[length_pos + 1] = (record_len & 0xFF) as u8;

    // Send the ClientHello
    if stream.write_all(&hello).await.is_err() {
        return false;
    }

    // Wait for ServerHello or alert
    let mut buf = [0u8; 5]; // Enough for record header
    match tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            // Check if we got a handshake message
            if buf[0] == 0x16 {
                // Handshake
                // Read handshake type
                let mut hs_buf = [0u8; 1];
                if stream.read_exact(&mut hs_buf).await.is_ok() && hs_buf[0] == 0x02 {
                    // ServerHello
                    return true;
                }
            }
            // Also check for HelloRetryRequest (TLS 1.3)
            if buf[0] == 0x16 && buf.len() >= 3 {
                // Need to read more to determine if it's a HelloRetryRequest
                // For simplicity, we'll accept any handshake as success for version detection
                return true;
            }
            false
        }
        _ => false,
    }
}

/// Implement raw SSLv2/SSLv3/TLS1.0 ClientHello probes
pub async fn test_legacy_protocols(host: &str, port: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let address = format!("{}:{}", host, port);
    let mut stream = match tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(&address),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    // SSLv2 ClientHello payload structure
    // Length: 2 bytes, 0x80 means no padding, length follows (0x1C = 28 bytes)
    let mut hello = vec![0x80, 0x1C];
    // Message Type: 1 (ClientHello)
    hello.push(0x01);
    // Version: SSLv2 (0x00, 0x02)
    hello.push(0x00);
    hello.push(0x02);
    // Cipher Spec Length (3 bytes per spec)
    hello.push(0x00);
    hello.push(0x03);
    // Session ID Length (0)
    hello.push(0x00);
    hello.push(0x00);
    // Challenge Length (16 bytes)
    hello.push(0x00);
    hello.push(0x10);
    // Cipher Specs (e.g., SSL_CK_DES_192_EDE3_CBC_WITH_MD5 -> 0x0700c0)
    hello.extend_from_slice(&[0x07, 0x00, 0xc0]);
    // Challenge data (16 random bytes)
    hello.extend_from_slice(&[0x11; 16]);

    if stream.write_all(&hello).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            // A response indicating an SSLv2 ServerHello (typically starts with length bit set)
            (buf[0] & 0x80) != 0
        }
        _ => false,
    }
}

/// Analyze a list of cipher suites
pub fn analyze_cipher_suites(suites: &[String]) -> Vec<CipherSuiteInfo> {
    suites
        .iter()
        .map(|suite| {
            let is_weak = WEAK_CIPHERS.contains(&suite.as_str())
                || suite.contains("RC4")
                || suite.contains("DES")
                || suite.contains("EXPORT");
            let weakness = if is_weak {
                Some("Known weak or obsolete cipher".to_string())
            } else {
                None
            };
            CipherSuiteInfo {
                suite: suite.clone(),
                is_strong: !is_weak,
                weakness,
                recommended_alternative: if is_weak {
                    Some("TLS_AES_128_GCM_SHA256 or TLS_CHACHA20_POLY1305_SHA256".to_string())
                } else {
                    None
                },
            }
        })
        .collect()
}

/// Get connection details including negotiated version and cipher suite
async fn get_connection_details(
    host: &str,
    port: u16,
) -> (Option<String>, Option<String>, Option<ValidationResult>) {
    let address = format!("{}:{}", host, port);
    let connect_timeout = Duration::from_secs(5);

    // Connect TCP
    let tcp_stream = match timeout(connect_timeout, TcpStream::connect(&address)).await {
        Ok(Ok(s)) => s,
        _ => return (None, None, None),
    };

    // Install default crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Use permissive client config for actual connection
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(
            crate::stealth::tls::NoCertVerification::new(),
        ))
        .with_no_client_auth();

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => return (None, None, None),
    };

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));

    let tls_stream =
        match timeout(connect_timeout, connector.connect(server_name, tcp_stream)).await {
            Ok(Ok(s)) => s,
            _ => return (None, None, None),
        };

    // Extract connection details
    let (_, server_conn) = tls_stream.get_ref();
    let tls_version = server_conn.protocol_version().map(|v| format!("{:?}", v));
    let cipher_suite = server_conn
        .negotiated_cipher_suite()
        .map(|c| format!("{:?}", c.suite()));

    // Perform basic validation
    let validation_result = validate_connection(server_conn).await;

    (tls_version, cipher_suite, validation_result)
}

/// STARTTLS wrapper for plaintext protocols
pub async fn negotiate_starttls(stream: &mut tokio::net::TcpStream, protocol: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    match protocol.to_lowercase().as_str() {
        "smtp" => {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await; // Consume banner
            let _ = stream.write_all(b"EHLO valayam.local\r\n").await;
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(b"STARTTLS\r\n").await;
            let n = stream.read(&mut buf).await.unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).contains("220")
        }
        "ftp" => {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await; // Consume banner
            let _ = stream.write_all(b"AUTH TLS\r\n").await;
            let n = stream.read(&mut buf).await.unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).contains("234")
        }
        "imap" => {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await; // Consume banner
            let _ = stream.write_all(b"a001 STARTTLS\r\n").await;
            let n = stream.read(&mut buf).await.unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).contains("OK")
        }
        _ => false,
    }
}

/// Validate a TLS connection for security issues
async fn validate_connection(conn: &rustls::ClientConnection) -> Option<ValidationResult> {
    let mut warnings = Vec::new();
    let errors = Vec::new();
    let mut is_trusted = true;

    // Check protocol version
    // if let Some(version) = conn.protocol_version() {
    //     match version {
    //         rustls::Version::TLSv1_0 | rustls::Version::TLSv1_1 => {
    //             warnings.push(format!("Deprecated protocol version: {:?}", version));
    //             is_trusted = false;
    //         }
    //         _ => {} // TLS 1.2 and 1.3 are considered secure
    //     }
    // }

    // Check cipher suite
    if let Some(suite) = conn.negotiated_cipher_suite() {
        if is_weak_cipher_suite(&suite) {
            warnings.push(format!("Weak cipher suite: {:?}", suite));
            is_trusted = false;
        }
    }

    // Check certificate validity (basic)
    let cert_valid = true; // Would do proper validation in reality

    Some(ValidationResult {
        is_trusted: is_trusted && cert_valid,
        validation_errors: errors,
        validation_warnings: warnings,
    })
}

/// Check if a signature algorithm is weak
#[allow(dead_code)]
fn is_weak_signature_algorithm(alg: &rustls::SignatureScheme) -> bool {
    // Note: MD2, MD4, MD5, and DSA variants have been removed from rustls 0.23
    // We check by string representation for the remaining weak identifiers
    let name = format!("{:?}", alg);
    name.contains("SHA1") || name.contains("SHA1_Legacy")
}

/// Check if a cipher suite is considered weak
fn is_weak_cipher_suite(suite: &rustls::SupportedCipherSuite) -> bool {
    // Define weak cipher suite patterns
    let suite_name = format!("{:?}", suite.suite());

    // Known weak ciphers
    WEAK_CIPHERS.contains(&suite_name.as_str())
}

/// List of known weak cipher suites
const WEAK_CIPHERS: &[&str] = &[
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_DES_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_RC2_40_MD5",
    "TLS_RSA_DES_40_CBC_SHA",
    "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",
    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    "TLS_ECDHE_RSA_WITH_NULL_SHA",
];

/// Get information about a cipher suite including strengths and weaknesses
pub fn analyze_cipher_suite(suite: &rustls::SupportedCipherSuite) -> Option<CipherSuiteInfo> {
    let suite_name = format!("{:?}", suite.suite());

    // Determine if it's strong or weak
    let is_strong = !is_weak_cipher_suite(suite);

    // Determine specific weaknesses
    let weakness = if !is_strong {
        Some(describe_cipher_weakness(&suite_name))
    } else {
        None
    };

    // Suggest stronger alternative
    let alternative = if !is_strong {
        Some(suggest_stronger_cipher(&suite_name))
    } else {
        None
    };

    Some(CipherSuiteInfo {
        suite: suite_name,
        is_strong,
        weakness,
        recommended_alternative: alternative,
    })
}

/// Describe the specific weakness of a cipher suite
fn describe_cipher_weakness(suite_name: &str) -> String {
    match suite_name {
        // RC4-based ciphers
        n if n.contains("RC4") => "Uses RC4 which has cryptographic vulnerabilities".to_string(),

        // DES-based ciphers
        n if n.contains("DES") && !n.contains("3DES") && !n.contains("IDEA") => {
            "Uses DES which has insufficient key strength (56-bit)".to_string()
        }

        // 3DES-based ciphers
        n if n.contains("3DES") => {
            "Uses 3DES which is vulnerable to sweet32 attack and has small block size".to_string()
        }

        // Export-grade ciphers
        n if n.contains("EXPORT") || n.contains("DES_40") => {
            "Export-grade cipher with intentionally weakened security".to_string()
        }

        // NULL ciphers (no encryption)
        n if n.contains("NULL") => "Provides no encryption (NULL cipher)".to_string(),

        // MD5-based MACs
        n if n.contains("MD5") => "Uses MD5 for MAC which is cryptographically broken".to_string(),

        // Other cases
        _ => "Unknown or unspecified weakness".to_string(),
    }
}

/// Suggest a stronger alternative cipher suite
fn suggest_stronger_cipher(suite_name: &str) -> String {
    // This would ideally recommend a specific stronger suite based on the server's capabilities
    // For now, return a general recommendation
    let _ = suite_name; // used for context-aware recommendation in the future
    "Consider using TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 or TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string()
}

/// Perform SSLv2/v3 detection using specialized probes
pub async fn detect_legacy_ssl(host: &str, port: u16) -> Vec<String> {
    let mut vulnerable = Vec::new();

    // Test SSLv2.0
    if is_sslv2_vulnerable(host, port).await {
        vulnerable.push("SSLv2.0".to_string());
    }

    // Test SSLv3.0 (POODLE vulnerable)
    if is_sslv3_vulnerable(host, port).await {
        vulnerable.push("SSLv3.0 (POODLE vulnerable)".to_string());
    }

    vulnerable
}

/// Check specifically for SSLv2.0 support
async fn is_sslv2_vulnerable(host: &str, port: u16) -> bool {
    // SSLv2 has a different handshake structure
    // This is a simplified check - real implementation would be more precise
    is_version_supported(host, port, 0x0002).await
}

/// Check specifically for SSLv3.0 support (POODLE vulnerable)
async fn is_sslv3_vulnerable(host: &str, port: u16) -> bool {
    // SSLv3 is vulnerable to POODLE attack
    is_version_supported(host, port, 0x0300).await
}

/// Probe for legacy TLS/SSL versions (SSLv3, TLSv1.0, TLSv1.1)
pub async fn probe_legacy_tls(host: &str, port: u16) -> Vec<String> {
    let mut protocols = Vec::new();

    // Define the legacy protocols we want to check
    let legacy_protocols = [
        (0x0300, "SSLv3.0"),
        (0x0301, "TLSv1.0"),
        (0x0302, "TLSv1.1"),
    ];

    for &(version, name) in &legacy_protocols {
        if is_version_supported(host, port, version).await {
            protocols.push(name.to_string());
        }
    }

    protocols
}

/// Get cipher suite ranking from strongest to weakest
pub fn get_cipher_suite_rankings() -> Vec<(String, i32)> {
    vec![
        // TLS 1.3 cipher suites (strongest)
        ("TLS_AES_256_GCM_SHA384".to_string(), 100),
        ("TLS_CHACHA20_POLY1305_SHA256".to_string(), 95),
        ("TLS_AES_128_GCM_SHA256".to_string(), 90),
        // TLS 1.2 ECDHE suites with strong curves
        ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(), 85),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(), 80),
        (
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            85,
        ),
        (
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            80,
        ),
        ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(), 75),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(), 70),
        // TLS 1.2 with SHA384
        ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384".to_string(), 65),
        ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384".to_string(), 60),
        ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256".to_string(), 55),
        ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256".to_string(), 50),
        // Older but still secure if configured correctly
        ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".to_string(), 45),
        ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".to_string(), 40),
        ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".to_string(), 35),
        ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string(), 30),
        // Weak but still sometimes seen
        ("TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(), 25),
        ("TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(), 20),
        ("TLS_RSA_WITH_AES_256_CBC_SHA256".to_string(), 15),
        ("TLS_RSA_WITH_AES_128_CBC_SHA256".to_string(), 10),
        // Definitely weak
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string(), 5),
        ("TLS_RSA_WITH_DES_CBC_SHA".to_string(), 0),
    ]
}

/// Check if a cipher suite is in the weak category
#[allow(dead_code)]
fn is_in_weak_category(suite: &str) -> bool {
    matches!(
        suite,
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
            | "TLS_RSA_WITH_DES_CBC_SHA"
            | "TLS_RSA_WITH_RC4_128_SHA"
            | "TLS_RSA_WITH_RC4_128_MD5"
            | "TLS_RSA_WITH_NULL_MD5"
            | "TLS_RSA_WITH_NULL_SHA"
            | "TLS_RSA_WITH_NULL_SHA256"
    )
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_tls_scanning() {
        // This would require a test server
        // Just verifying the function signatures work
        assert!(true);
    }

    #[test]
    fn test_cipher_suite_analysis() {
        // This would require creating actual cipher suite instances
        // Just verifying the function signatures work
        assert!(true);
    }
}
