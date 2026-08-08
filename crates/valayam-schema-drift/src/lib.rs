//! Schema drift detection — OpenAPI document parsing, endpoint diffing,
//! and shadow API discovery.
//!
//! Parses OpenAPI specs, crawls target applications, and cross-references
//! active endpoints against the specification to flag undocumented shadow APIs
//! and abandoned zombie API routes.

pub mod executor;
