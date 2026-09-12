use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

use crate::testing_category::TestingCategory;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TemplateInfo {
    pub name: String,
    pub severity: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<TestingCategory>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub compliance: HashMap<String, String>,
}

impl TemplateInfo {
    /// Create a new TemplateInfo
    pub fn new(name: impl Into<String>, severity: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            severity: severity.into(),
            author: None,
            description: None,
            category: None,
            tags: vec![],
            compliance: HashMap::new(),
        }
    }

    pub fn with_author(mut self, author: Option<String>) -> Self {
        self.author = author;
        self
    }

    pub fn with_description(mut self, description: Option<String>) -> Self {
        self.description = description;
        self
    }

    pub fn with_category(mut self, category: Option<TestingCategory>) -> Self {
        self.category = category;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_compliance(mut self, compliance: HashMap<String, String>) -> Self {
        self.compliance = compliance;
        self
    }
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
    fn category(&self) -> Option<&TestingCategory>;
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
    fn category(&self) -> Option<&TestingCategory> {
        self.category.as_ref()
    }
}
