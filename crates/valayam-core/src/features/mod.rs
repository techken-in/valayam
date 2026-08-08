//! Feature modules for the core scanning engine.
//!
//! Each submodule implements a vertical slice of scanning capability:
//! HTTP scanning, crawling, extraction, schema drift detection, threat intel,
//! UI proxy, and helper functions.

pub mod crawler;
pub mod extractors;
pub mod helpers;
pub mod http_scan;
pub mod schema_drift;
pub mod threat_intel;
pub mod ui_proxy;
