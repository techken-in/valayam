use serde::{Deserialize, Serialize};

/// Represents a generic template configuration for a third-party marketplace plugin.
/// This allows templates to invoke WASM plugins using a dynamic schema without modifying
/// the core engine's statically typed structures.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomPluginTemplate {
    /// The ID/name of the plugin to invoke (e.g., 'api-fuzzer', 'csp-audit')
    pub id: String,
    
    /// Arbitrary configuration data passed to the plugin
    #[serde(flatten)]
    pub config: serde_json::Value,
}
