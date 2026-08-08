//! Re-export of `ScannerError` from the `valayam-error` crate.
//!
//! This module exists for backwards compatibility — all consumers
//! import `ScannerError` via `valayam_models::error::ScannerError`.
//! Direct imports from `valayam_error` are also supported.

pub use valayam_error::ScannerError;
