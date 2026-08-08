use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TemplateInfo {
    pub name: String,
    pub severity: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub compliance: HashMap<String, String>,
}

/// Object-safe trait to decouple template metadata consumers from the concrete TemplateInfo struct.
/// Allows executors to accept `&dyn TemplateMetadata` instead of `&TemplateInfo`.
///
/// Requires `Debug + Sync + Send` so that trait objects can be used across `.await`
/// points in async executors and included in `#[tracing::instrument]` spans.
pub trait TemplateMetadata: Debug + Sync + Send {
    fn template_name(&self) -> &str;
    fn template_severity(&self) -> &str;
    fn description(&self) -> Option<&str>;
    fn author(&self) -> Option<&str>;
    fn tags(&self) -> &[String];
    fn compliance(&self) -> &HashMap<String, String>;
}

impl TemplateMetadata for TemplateInfo {
    fn template_name(&self) -> &str {
        &self.name
    }
    fn template_severity(&self) -> &str {
        &self.severity
    }
    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    fn author(&self) -> Option<&str> {
        self.author.as_deref()
    }
    fn tags(&self) -> &[String] {
        &self.tags
    }
    fn compliance(&self) -> &HashMap<String, String> {
        &self.compliance
    }
}
