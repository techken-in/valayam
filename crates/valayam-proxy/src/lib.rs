//! UI proxy — MITM proxy for intercepting and inspecting web traffic.
//!
//! Provides certificate authority generation, TLS interception,
//! and proxy server for dynamic traffic analysis.

pub mod cert_auth;
pub mod mitm;
pub mod server;
pub mod state;
