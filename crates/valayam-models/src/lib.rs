//! Core data models for the Valayam scanner.
//!
//! Defines ScanResult, FindingOwned, PluginOutcomeKind, PluginMetrics,
//! PluginHealth, TemplateInfo, TemplateMetadata, and the template section
//! schemas. All scanner crates depend on these type definitions.

pub mod bridge;
pub mod error;
pub mod finding;
pub mod result;
pub mod template_info;
pub mod templates;
pub mod testing_category;

pub use finding::{FindingOwned, PluginHealth, PluginMetrics, PluginOutcomeKind};
pub use result::ScanResult;
pub use template_info::{TemplateInfo, TemplateMetadata};
pub use testing_category::TestingCategory;
