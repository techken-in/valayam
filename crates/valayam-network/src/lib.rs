//! Low-level network primitives for multi-protocol scanning.
//!
//! Provides HTTP client with WAF evasion, TLS with custom cipher negotiation,
//! TCP/UDP port scanning, DNS resolution, proxy rotation, and stealth/user-agent
//! rotation. Shared across all network-dependent scan features.
pub mod network;
pub mod network_metrics;
pub mod stealth;
