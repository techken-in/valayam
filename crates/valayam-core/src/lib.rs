#![warn(missing_docs)]
//! Core scanning engine for Valayam network security scanner.
//!
//! Provides HTTP scanning, crawling, template execution, threat intelligence,
//! UI proxy, and distribution coordination. This is the primary crate where
//! feature plugins register and execute against targets.
/// Documentation for this item.
pub mod config;
pub mod core;
pub mod features;
pub use valayam_network::network;
pub use valayam_network::stealth;
pub mod distribution;
pub mod template;

// Re-exported from valayam-proto (single source of truth)
pub use valayam_proto::plugin as plugin_rpc;
pub use valayam_proto::valayam as rpc;
