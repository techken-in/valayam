//! Unified error types for the Valayam scanner ecosystem.
//!
//! `ScannerError` is the primary error enum used across all scanner crates.
//! It provides fine-grained variants for every feature module, retryability
//! classification, and SIEM-compatible serialization.

use std::io;
use std::net::AddrParseError;
use thiserror::Error;

/// Unified error enum for all scanner operations.
/// Production-grade error handling with fine-grained variants for every
/// feature module. All variants serialise cleanly for SIEM consumption.
#[derive(Error, Debug)]
pub enum ScannerError {
    // ── Template/I/O ──
    #[error("Failed to read template file: {0}")]
    TemplateReadError(#[source] io::Error),

    #[error("Failed to parse YAML template: {0}")]
    TemplateParseError(#[from] serde_yaml::Error),

    #[error("Template validation failed: {0}")]
    TemplateValidationError(String),

    #[error("Variable resolution error: {0}")]
    VariableResolutionError(String),

    // ── HTTP Client ──
    #[error("Failed to build HTTP client: {0}")]
    HttpClientError(#[from] reqwest::Error),

    #[error("Invalid HTTP Method defined in template: {0}")]
    InvalidHttpMethod(String),

    #[error("HTTP scan execution failed: {0}")]
    HttpScanError(String),

    #[error("Too many redirects followed")]
    TooManyRedirects,

    // ── Script Engine ──
    #[error("Failed to initialize script engine: {0}")]
    ScriptEngineInitError(String),

    #[error("Failed to execute script: {0}")]
    ScriptExecutionError(String),

    // ── Network ──
    #[error("Network connection failed: {0}")]
    NetworkError(#[from] tokio::io::Error),

    #[error("DNS resolution failed for {host}: {error}")]
    DnsResolutionError { host: String, error: String },

    #[error("TCP connection failed to {host}:{port}: {error}")]
    TcpConnectionError {
        host: String,
        port: u16,
        error: String,
    },

    #[error("UDP timeout or failure for {host}:{port}: {error}")]
    UdpError {
        host: String,
        port: u16,
        error: String,
    },

    // ‾─ TLS ──
    #[error("TLS handshake failed for {host}:{port}: {error}")]
    TlsHandshakeError {
        host: String,
        port: u16,
        error: String,
    },

    #[error("TLS certificate parsing failed: {0}")]
    TlsCertParseError(String),

    // Input/Validation
    #[error("Invalid target specification: {0}")]
    InvalidTarget(String),

    #[error("Invalid port specification: {0}")]
    InvalidPort(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Circuit breaker is open")]
    CircuitBreakerOpen,

    // Configuration
    #[error("Invalid configuration: {0}")]
    ConfigurationError(String),

    // Resource
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    // Timeout
    #[error("Operation timed out: {0}")]
    TimeoutError(String),

    // Parsing
    #[error("Failed to parse response data: {0}")]
    ParseError(String),

    //──── Crypto/TLS ──
    #[error("Certificate validation failed: {0}")]
    CertificateValidationError(String),

    #[error("Invalid cipher suite: {0}")]
    InvalidCipherSuite(String),

    // ── Proxy santé ──
    #[error("Proxy connection failed: {0}")]
    ProxyError(String),

    // ── Data Conversion ──
    #[error("Failed to parse address: {0}")]
    AddressParseError(#[from] AddrParseError),

    // ── Encoding ──
    #[error("Invalid UTF-8 data: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    // ── Feature-Module Specific ──
    #[error("Crawler operation failed: {0}")]
    CrawlerError(String),

    #[error("Data extraction failed: {0}")]
    ExtractorError(String),

    #[error("Schema drift detection failed: {0}")]
    SchemaDriftError(String),

    #[error("UI proxy / MITM operation failed: {0}")]
    UiProxyError(String),

    #[error("OOB interaction verification failed: {0}")]
    OobError(String),

    // ── Registry/Plugin ──
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),

    #[error("Plugin initialization failed: {0}")]
    PluginInitializationError(String),

    #[error("Plugin execution failed: {0}")]
    PluginExecutionError(String),

    // ── Audit/Report ──
    #[error("Audit logging failed: {0}")]
    AuditError(String),

    #[error("Report generation failed: {0}")]
    ReportError(String),

    // ── eBPF/Kernel ──
    #[error("eBPF agent error: {0}")]
    EbpfError(String),

    // ── CLI/State ──
    #[error("CLI operation failed: {0}")]
    CliError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    // ── Fallback ──
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

// Implement serialization traits for SIEM/logging compatibility
impl serde::Serialize for ScannerError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        // Create a structured representation for better log analysis
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ScannerError", 3)?;
        state.serialize_field("error_type", &self.to_string())?;
        state.serialize_field("message", &self.to_string())?;
        state.serialize_field("is_retryable", &self.is_retryable())?;
        state.end()
    }
}

impl ScannerError {
    /// Determine if an error is retryable (useful for resilient scanning)
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ScannerError::NetworkError(_)
                | ScannerError::TimeoutError(_)
                | ScannerError::RateLimitExceeded
                | ScannerError::CircuitBreakerOpen
                | ScannerError::TlsHandshakeError { .. }
                | ScannerError::DnsResolutionError { .. }
                | ScannerError::TcpConnectionError { .. }
                | ScannerError::UdpError { .. }
                | ScannerError::ProxyError(_)
                | ScannerError::HttpScanError(_)
                | ScannerError::DatabaseError(_)
                | ScannerError::TooManyRedirects
                | ScannerError::OobError(_)
        )
    }

    /// Get a standardized error code for categorization
    pub fn error_code(&self) -> &'static str {
        match self {
            ScannerError::TemplateReadError(_) => "TEMPLATE_READ_ERROR",
            ScannerError::TemplateParseError(_) => "TEMPLATE_PARSE_ERROR",
            ScannerError::TemplateValidationError(_) => "TEMPLATE_VALIDATION_ERROR",
            ScannerError::VariableResolutionError(_) => "VARIABLE_RESOLUTION_ERROR",
            ScannerError::HttpClientError(_) => "HTTP_CLIENT_ERROR",
            ScannerError::InvalidHttpMethod(_) => "INVALID_HTTP_METHOD",
            ScannerError::HttpScanError(_) => "HTTP_SCAN_ERROR",
            ScannerError::TooManyRedirects => "TOO_MANY_REDIRECTS",
            ScannerError::ScriptEngineInitError(_) => "SCRIPT_INIT_ERROR",
            ScannerError::ScriptExecutionError(_) => "SCRIPT_EXECUTION_ERROR",
            ScannerError::NetworkError(_) => "NETWORK_ERROR",
            ScannerError::DnsResolutionError { .. } => "DNS_RESOLUTION_ERROR",
            ScannerError::TcpConnectionError { .. } => "TCP_CONNECTION_ERROR",
            ScannerError::UdpError { .. } => "UDP_ERROR",
            ScannerError::TlsHandshakeError { .. } => "TLS_HANDSHAKE_ERROR",
            ScannerError::TlsCertParseError(_) => "TLS_CERT_PARSE_ERROR",
            ScannerError::InvalidTarget(_) => "INVALID_TARGET",
            ScannerError::InvalidPort(_) => "INVALID_PORT",
            ScannerError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            ScannerError::CircuitBreakerOpen => "CIRCUIT_BREAKER_OPEN",
            ScannerError::ConfigurationError(_) => "CONFIGURATION_ERROR",
            ScannerError::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
            ScannerError::TimeoutError(_) => "TIMEOUT_ERROR",
            ScannerError::ParseError(_) => "PARSE_ERROR",
            ScannerError::CertificateValidationError(_) => "CERTIFICATE_VALIDATION_ERROR",
            ScannerError::InvalidCipherSuite(_) => "INVALID_CIPHER_SUITE",
            ScannerError::ProxyError(_) => "PROXY_ERROR",
            ScannerError::AddressParseError(_) => "ADDRESS_PARSE_ERROR",
            ScannerError::Utf8Error(_) => "UTF8_ERROR",
            ScannerError::CrawlerError(_) => "CRAWLER_ERROR",
            ScannerError::ExtractorError(_) => "EXTRACTOR_ERROR",
            ScannerError::SchemaDriftError(_) => "SCHEMA_DRIFT_ERROR",
            ScannerError::UiProxyError(_) => "UI_PROXY_ERROR",
            ScannerError::OobError(_) => "OOB_ERROR",
            ScannerError::PluginNotFound(_) => "PLUGIN_NOT_FOUND",
            ScannerError::PluginInitializationError(_) => "PLUGIN_INITIALIZATION_ERROR",
            ScannerError::PluginExecutionError(_) => "PLUGIN_EXECUTION_ERROR",
            ScannerError::AuditError(_) => "AUDIT_ERROR",
            ScannerError::ReportError(_) => "REPORT_ERROR",
            ScannerError::EbpfError(_) => "EBPF_ERROR",
            ScannerError::CliError(_) => "CLI_ERROR",
            ScannerError::DatabaseError(_) => "DATABASE_ERROR",
            ScannerError::Other(_) => "OTHER_ERROR",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constructor & Display tests ────────────────────────────────────────

    #[test]
    fn test_template_read_error_display() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = ScannerError::TemplateReadError(io_err);
        assert!(err.to_string().contains("file not found"));
        assert_eq!(err.error_code(), "TEMPLATE_READ_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_template_parse_error_from_yaml() {
        let yaml_result: Result<serde_yaml::Value, _> = serde_yaml::from_str("'unclosed string");
        let yaml_err = yaml_result.unwrap_err();
        let err: ScannerError = yaml_err.into();
        assert_eq!(err.error_code(), "TEMPLATE_PARSE_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_template_validation_error() {
        let err = ScannerError::TemplateValidationError("missing id field".into());
        assert_eq!(
            err.to_string(),
            "Template validation failed: missing id field"
        );
        assert_eq!(err.error_code(), "TEMPLATE_VALIDATION_ERROR");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn test_http_client_error() {
        let err = ScannerError::HttpClientError(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(10))
                .build()
                .unwrap()
                .get("https://192.0.2.1:1/")
                .timeout(std::time::Duration::from_millis(10))
                .send()
                .await
                .unwrap_err(),
        );
        assert_eq!(err.error_code(), "HTTP_CLIENT_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_invalid_http_method() {
        let err = ScannerError::InvalidHttpMethod("INVALID".into());
        assert_eq!(
            err.to_string(),
            "Invalid HTTP Method defined in template: INVALID"
        );
        assert_eq!(err.error_code(), "INVALID_HTTP_METHOD");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_script_errors() {
        let init_err = ScannerError::ScriptEngineInitError("rhai engine failed".into());
        assert!(init_err.to_string().contains("rhai engine failed"));
        assert_eq!(init_err.error_code(), "SCRIPT_INIT_ERROR");
        assert!(!init_err.is_retryable());

        let exec_err = ScannerError::ScriptExecutionError("timeout".into());
        assert!(exec_err.to_string().contains("timeout"));
        assert_eq!(exec_err.error_code(), "SCRIPT_EXECUTION_ERROR");
        assert!(!exec_err.is_retryable());
    }

    #[test]
    fn test_network_errors_retryable() {
        let net_err = ScannerError::NetworkError(tokio::io::Error::from(io::ErrorKind::TimedOut));
        assert!(net_err.is_retryable());
        assert_eq!(net_err.error_code(), "NETWORK_ERROR");

        let timeout_err = ScannerError::TimeoutError("connection timed out".into());
        assert!(timeout_err.is_retryable());
        assert_eq!(timeout_err.error_code(), "TIMEOUT_ERROR");

        let rate_err = ScannerError::RateLimitExceeded;
        assert!(rate_err.is_retryable());
        assert_eq!(rate_err.error_code(), "RATE_LIMIT_EXCEEDED");
    }

    #[test]
    fn test_dns_resolution_error() {
        let err = ScannerError::DnsResolutionError {
            host: "example.com".into(),
            error: "NXDOMAIN".into(),
        };
        assert_eq!(
            err.to_string(),
            "DNS resolution failed for example.com: NXDOMAIN"
        );
        assert_eq!(err.error_code(), "DNS_RESOLUTION_ERROR");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_tcp_connection_error() {
        let err = ScannerError::TcpConnectionError {
            host: "10.0.0.1".into(),
            port: 8080,
            error: "Connection refused".into(),
        };
        assert_eq!(
            err.to_string(),
            "TCP connection failed to 10.0.0.1:8080: Connection refused"
        );
        assert_eq!(err.error_code(), "TCP_CONNECTION_ERROR");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_udp_error() {
        let err = ScannerError::UdpError {
            host: "10.0.0.1".into(),
            port: 5353,
            error: "timeout".into(),
        };
        assert_eq!(
            err.to_string(),
            "UDP timeout or failure for 10.0.0.1:5353: timeout"
        );
        assert_eq!(err.error_code(), "UDP_ERROR");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_tls_handshake_error() {
        let err = ScannerError::TlsHandshakeError {
            host: "example.com".into(),
            port: 443,
            error: "certificate expired".into(),
        };
        assert_eq!(
            err.to_string(),
            "TLS handshake failed for example.com:443: certificate expired"
        );
        assert_eq!(err.error_code(), "TLS_HANDSHAKE_ERROR");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_tls_cert_parse_error() {
        let err = ScannerError::TlsCertParseError("invalid ASN1".into());
        assert_eq!(
            err.to_string(),
            "TLS certificate parsing failed: invalid ASN1"
        );
        assert_eq!(err.error_code(), "TLS_CERT_PARSE_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_invalid_target_and_port() {
        let target_err = ScannerError::InvalidTarget("not a url".into());
        assert_eq!(
            target_err.to_string(),
            "Invalid target specification: not a url"
        );
        assert_eq!(target_err.error_code(), "INVALID_TARGET");
        assert!(!target_err.is_retryable());

        let port_err = ScannerError::InvalidPort("99999".into());
        assert_eq!(port_err.to_string(), "Invalid port specification: 99999");
        assert_eq!(port_err.error_code(), "INVALID_PORT");
        assert!(!port_err.is_retryable());
    }

    #[test]
    fn test_configuration_and_resource_errors() {
        let cfg_err = ScannerError::ConfigurationError("missing api key".into());
        assert_eq!(cfg_err.error_code(), "CONFIGURATION_ERROR");
        assert!(!cfg_err.is_retryable());

        let res_err = ScannerError::ResourceExhausted("too many open files".into());
        assert_eq!(res_err.error_code(), "RESOURCE_EXHAUSTED");
        assert!(!res_err.is_retryable());
    }

    #[test]
    fn test_parse_error() {
        let err = ScannerError::ParseError("invalid json".into());
        assert_eq!(
            err.to_string(),
            "Failed to parse response data: invalid json"
        );
        assert_eq!(err.error_code(), "PARSE_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_certificate_and_cipher_errors() {
        let cert_err = ScannerError::CertificateValidationError("self-signed".into());
        assert_eq!(cert_err.error_code(), "CERTIFICATE_VALIDATION_ERROR");
        assert!(!cert_err.is_retryable());

        let cipher_err = ScannerError::InvalidCipherSuite("TLS_NULL".into());
        assert_eq!(cipher_err.error_code(), "INVALID_CIPHER_SUITE");
        assert!(!cipher_err.is_retryable());
    }

    #[test]
    fn test_proxy_error_retryable() {
        let err = ScannerError::ProxyError("proxy unreachable".into());
        assert_eq!(err.error_code(), "PROXY_ERROR");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_address_parse_error_from_std() {
        let addr_err = "not a socket addr"
            .parse::<std::net::SocketAddr>()
            .unwrap_err();
        let err: ScannerError = addr_err.into();
        assert_eq!(err.error_code(), "ADDRESS_PARSE_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_utf8_error_from_std() {
        let bytes = vec![0xFF, 0xFE, 0x00];
        let str_err = String::from_utf8(bytes).unwrap_err();
        let err = ScannerError::Utf8Error(str_err);
        assert_eq!(err.error_code(), "UTF8_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_plugin_errors() {
        let nf = ScannerError::PluginNotFound("ssh_scan".into());
        assert_eq!(nf.to_string(), "Plugin not found: ssh_scan");
        assert_eq!(nf.error_code(), "PLUGIN_NOT_FOUND");
        assert!(!nf.is_retryable());

        let init = ScannerError::PluginInitializationError("bad config".into());
        assert!(init.to_string().contains("bad config"));
        assert_eq!(init.error_code(), "PLUGIN_INITIALIZATION_ERROR");
        assert!(!init.is_retryable());

        let exec = ScannerError::PluginExecutionError("oom".into());
        assert_eq!(exec.to_string(), "Plugin execution failed: oom");
        assert_eq!(exec.error_code(), "PLUGIN_EXECUTION_ERROR");
        assert!(!exec.is_retryable());
    }

    #[test]
    fn test_other_error_boxed() {
        let io_err = io::Error::new(io::ErrorKind::Other, "generic io error");
        let err = ScannerError::Other(Box::new(io_err));
        assert!(err.to_string().contains("generic io error"));
        assert_eq!(err.error_code(), "OTHER_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_non_retryable_errors_exhaustive() {
        let cases: Vec<ScannerError> = vec![
            ScannerError::TemplateReadError(io::Error::new(io::ErrorKind::NotFound, "")),
            ScannerError::TemplateValidationError("".into()),
            ScannerError::InvalidHttpMethod("".into()),
            ScannerError::ScriptEngineInitError("".into()),
            ScannerError::ScriptExecutionError("".into()),
            ScannerError::TlsCertParseError("".into()),
            ScannerError::InvalidTarget("".into()),
            ScannerError::InvalidPort("".into()),
            ScannerError::ConfigurationError("".into()),
            ScannerError::ResourceExhausted("".into()),
            ScannerError::ParseError("".into()),
            ScannerError::CertificateValidationError("".into()),
            ScannerError::InvalidCipherSuite("".into()),
            ScannerError::AddressParseError(
                "0.0.0.0:99999".parse::<std::net::SocketAddr>().unwrap_err(),
            ),
            ScannerError::Utf8Error(String::from_utf8(vec![0xFF]).unwrap_err()),
            ScannerError::PluginNotFound("".into()),
            ScannerError::PluginInitializationError("".into()),
            ScannerError::PluginExecutionError("".into()),
            ScannerError::Other(Box::new(io::Error::new(io::ErrorKind::Other, ""))),
        ];
        for err in &cases {
            assert!(
                !err.is_retryable(),
                "Expected non-retryable for: {:?}",
                err.error_code()
            );
        }
    }

    #[test]
    fn test_serialization_round_trip() {
        let err = ScannerError::TemplateValidationError("bad template".into());
        let json = serde_json::to_string(&err).expect("Should serialize");
        assert!(json.contains("Template validation failed: bad template"));

        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should parse JSON");
        assert_eq!(
            parsed["error_type"],
            "Template validation failed: bad template"
        );
        assert_eq!(
            parsed["message"],
            "Template validation failed: bad template"
        );
        assert_eq!(parsed["is_retryable"], false);
    }

    #[test]
    fn test_error_codes_are_unique() {
        use std::collections::HashSet;
        let mut codes = HashSet::new();

        let errs: Vec<ScannerError> = vec![
            ScannerError::TemplateReadError(io::Error::new(io::ErrorKind::NotFound, "")),
            ScannerError::TemplateValidationError("".into()),
            ScannerError::InvalidHttpMethod("".into()),
            ScannerError::HttpScanError("".into()),
            ScannerError::TooManyRedirects,
            ScannerError::CrawlerError("".into()),
            ScannerError::ExtractorError("".into()),
            ScannerError::SchemaDriftError("".into()),
            ScannerError::UiProxyError("".into()),
            ScannerError::OobError("".into()),
            ScannerError::AuditError("".into()),
            ScannerError::ReportError("".into()),
            ScannerError::EbpfError("".into()),
            ScannerError::CliError("".into()),
            ScannerError::DatabaseError("".into()),
        ];
        for e in &errs {
            assert!(
                codes.insert(e.error_code()),
                "Duplicate error code: {}",
                e.error_code()
            );
        }
    }

    #[test]
    fn test_http_scan_error() {
        let err = ScannerError::HttpScanError("request timed out".into());
        assert_eq!(err.error_code(), "HTTP_SCAN_ERROR");
        assert!(err.is_retryable());
        assert!(err.to_string().contains("request timed out"));
    }

    #[test]
    fn test_crawler_error() {
        let err = ScannerError::CrawlerError("spider loop detected".into());
        assert_eq!(err.error_code(), "CRAWLER_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_extractor_error() {
        let err = ScannerError::ExtractorError("regex compilation failed".into());
        assert_eq!(err.error_code(), "EXTRACTOR_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_schema_drift_error() {
        let err = ScannerError::SchemaDriftError("openapi parse error".into());
        assert_eq!(err.error_code(), "SCHEMA_DRIFT_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_ui_proxy_error() {
        let err = ScannerError::UiProxyError("certificate authority unavailable".into());
        assert_eq!(err.error_code(), "UI_PROXY_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_oob_error_retryable() {
        let err = ScannerError::OobError("DNS callback not received".into());
        assert_eq!(err.error_code(), "OOB_ERROR");
        assert!(err.is_retryable());
    }

    #[test]
    fn test_audit_error() {
        let err = ScannerError::AuditError("write-ahead-log full".into());
        assert_eq!(err.error_code(), "AUDIT_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_report_error() {
        let err = ScannerError::ReportError("PDF render engine unavailable".into());
        assert_eq!(err.error_code(), "REPORT_ERROR");
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_non_retryable_includes_new_variants() {
        let non_retryable: Vec<ScannerError> = vec![
            ScannerError::CrawlerError("".into()),
            ScannerError::ExtractorError("".into()),
            ScannerError::SchemaDriftError("".into()),
            ScannerError::UiProxyError("".into()),
            ScannerError::AuditError("".into()),
            ScannerError::ReportError("".into()),
            ScannerError::EbpfError("".into()),
            ScannerError::CliError("".into()),
        ];
        for err in &non_retryable {
            assert!(
                !err.is_retryable(),
                "Expected non-retryable: {:?}",
                err.error_code()
            );
        }
    }
}
