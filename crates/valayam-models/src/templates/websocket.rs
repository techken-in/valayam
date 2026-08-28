use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WebsocketTemplate {
    pub name: Option<String>,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<crate::templates::matcher::ResponseMatcher>,
    #[serde(default)]
    pub extractors: Vec<crate::templates::extractors::Extractor>,
}
