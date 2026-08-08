//! Network-dependent scan features for Valayam.
//!
//! Submodules provide scanning capabilities that require network connectivity:
//! DNS audit, network scan, port scan, TLS audit, OOB testing, and shell handlers.

pub mod dns_audit;
pub mod network_scan;
pub mod oob;
pub mod port_scan;
pub mod shells;
pub mod tls_audit;
