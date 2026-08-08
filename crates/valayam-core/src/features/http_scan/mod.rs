//! HTTP request scanning — sends crafted requests and analyzes responses.
//!
//! Supports custom methods, headers, body injection, follow-redirects,
//! and response matching for vulnerability detection.
//! Integrates variables.rs for dynamic `{{placeholder}}` substitutions.

/// Documentation for this item.
pub mod executor;
