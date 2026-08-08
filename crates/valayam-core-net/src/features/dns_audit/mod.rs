//! DNS audit scanning — DNS record enumeration and vulnerability detection.
//!
//! Supports A, AAAA, CNAME, TXT, MX querying via hickory-resolver.
//! Detects subdomain takeover and DNS rebinding vulnerabilities.
//! Attempts AXFR zone transfer as a fallback probe.

pub mod executor;
