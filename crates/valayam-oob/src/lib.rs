//! Out-of-Band (OOB) testing — callback-based vulnerability detection.
//!
//! Real HTTP/DNS server with correlation ID tracking, hit storage, and cleanup.
//! Supports TLS termination for HTTPS callbacks and WebSocket notifications.
//! Geographic and network path correlation for callback verification.

pub mod correlation;
pub mod executor;
pub mod server;
