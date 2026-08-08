//! TLS/SSL auditing — certificate extraction and cipher suite analysis.
//!
//! Extracts issuer, SANs, expiry, and signature algorithms from certificates.
//! Implements weak cipher detection and minimum TLS version enforcement.
//! Uses raw ClientHello probes to detect legacy SSLv3/TLSv1.0.

pub mod executor;
