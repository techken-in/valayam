//! Threat intelligence ingestion and correlation — now served from `valayam-threatintel` crate.
//!
//! Re-exports keep `valayam_core::features::threat_intel::*` paths working.

pub use valayam_threatintel::ingestion;
pub use valayam_threatintel::ioc_matcher;
