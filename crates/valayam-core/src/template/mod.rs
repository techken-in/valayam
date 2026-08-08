//! Template orchestration — loading, schema, and execution pipeline.
//!
//! Defines the VulnerabilityTemplate schema structure and orchestrates the
//! execution pipeline (HTTP → Network → Scripts) ensuring shared variable
//! context flows correctly through all stages.
pub use valayam_models::templates::schema;
/// Documentation for this item.
pub mod loader;
pub use loader::TemplateLoader;
