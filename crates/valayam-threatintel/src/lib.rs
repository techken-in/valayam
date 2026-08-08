//! Threat intelligence ingestion and correlation.
//!
//! Automated CISA KEV feed parsing, IOC cross-referencing against
//! extracted indicators, and dynamic template construction from TI data.
//! Persists TI data locally for offline scanning environments.

mod config;
pub mod ingestion;
pub mod ioc_matcher;
