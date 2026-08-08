//! Network primitives for multi-protocol scanning.
//!
//! HTTP client with stealth/WAF evasion, TCP/UDP port scanning,
//! DNS resolution (hickory-resolver), TLS handshake and certificate
//! extraction, and TOR proxy support.
pub mod dns;
pub mod http;
pub mod raw;
pub mod resilience;
pub mod ssrf_filter;
pub mod tcp;
pub mod tls;
pub mod tor;
pub mod udp;
