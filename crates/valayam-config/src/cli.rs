//! CLI environment-based config — loaded from env vars / .env file.

use serde::{Deserialize, Serialize};
use std::env;

/// Environment-based CLI configuration (VALAYAM_* vars + .env file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub valayam_registry_user: Option<String>,
    pub valayam_registry_pass: Option<String>,
    pub valayam_public_key: String,
    pub valayam_log: Option<String>,
    pub otel_exporter_otlp_endpoint: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl CliConfig {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        Self {
            valayam_registry_user: env::var("VALAYAM_REGISTRY_USER").ok(),
            valayam_registry_pass: env::var("VALAYAM_REGISTRY_PASS").ok(),
            valayam_public_key: env::var("VALAYAM_PUBLIC_KEY").unwrap_or_else(|_| {
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            }),
            valayam_log: env::var("VALAYAM_LOG").ok(),
            otel_exporter_otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
        }
    }
}
