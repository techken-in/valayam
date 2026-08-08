//! TCP/UDP network scanning — port range scanning with service identification.
//!
//! Concurrent TCP/UDP scanning with service identification, version extraction,
//! vulnerability assessment, and risk prioritization. HTTP GET fallback for
//! silent services is implemented in tcp::scan_ports.

pub mod executor;
pub mod parser;
