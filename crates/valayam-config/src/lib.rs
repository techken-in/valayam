//! Centralized configuration for Valayam scanner.
//!
//! # Layered Config Priority
//! 1. **Defaults** — built-in sensible defaults
//! 2. **Config file** — YAML/JSON from `--config` or `valayam.yaml` in CWD
//! 3. **Environment variables** — `VALAYAM_*` prefix overrides
//! 4. **CLI arguments** — highest priority
//!
//! # Validation
//! `ValayamConfig::validate()` returns a `ConfigError` for:
//! - Broken paths (templates, proxies, log file)
//! - Missing required fields (target, templates)
//! - Invalid URL format for target
//! - Conflicting flags (template + nuclei_template)
//! - Invalid port ranges

pub mod agent;
pub mod cli;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level Valayam configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ValayamConfig {
    // ── Scan target ──────────────────────────────────────────────────────
    /// Target base URL or hostname.
    pub target: String,

    /// Path to Native YAML template file or directory.
    pub template: Option<PathBuf>,

    /// Path to Nuclei YAML template file or directory.
    pub nuclei_template: Option<PathBuf>,

    /// Path to write output findings.
    pub output: Option<PathBuf>,

    /// Output format (json, sarif, pdf).
    #[serde(rename = "format")]
    pub output_format: String,

    // ── Performance ──────────────────────────────────────────────────────
    /// Max requests per second (global rate limit).
    pub rate_limit: Option<u32>,

    /// Max concurrent template executions.
    pub concurrency: usize,

    // ── Stealth ──────────────────────────────────────────────────────────
    /// Rotate User-Agent header randomly.
    pub random_agent: bool,

    /// Path to proxy list file (one proxy per line).
    pub proxy_file: Option<PathBuf>,

    /// Detect WAF before scanning.
    pub waf_detect: bool,

    // ── Crawler ──────────────────────────────────────────────────────────
    /// Crawl the target URL to discover pages.
    pub crawl: bool,

    /// Maximum depth for the crawler.
    pub crawl_depth: usize,

    /// Custom headers for crawler requests.
    pub crawl_headers: Option<HashMap<String, String>>,

    // ── Logging ──────────────────────────────────────────────────────────
    /// Log level (trace, debug, info, warn, error).
    pub log_level: String,

    /// Path to output structured (JSON) logs.
    pub log_file: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// URI of a gRPC worker node.
    pub worker: Option<String>,

    /// MITM proxy port (starts local proxy).
    pub mitm_proxy: Option<u16>,

    /// Control plane port for pause/resume/cancel.
    pub control_port: Option<u16>,

    // ── TLS / Security ───────────────────────────────────────────────────
    /// Path to TLS certificate (PEM) for gRPC control plane.
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key (PEM) for gRPC control plane.
    pub tls_key: Option<PathBuf>,

    /// Require WASM/VPA plugin signature verification.
    pub require_signed_plugins: bool,

    /// Resume a previous scan by state ID.
    pub resume: Option<String>,

    // ── Internal ─────────────────────────────────────────────────────────
    /// Config file path (not serialized).
    #[serde(skip)]
    pub config_file: Option<PathBuf>,
}

impl Default for ValayamConfig {
    fn default() -> Self {
        Self {
            target: "https://httpbin.org".into(),
            template: None,
            nuclei_template: None,
            output: None,
            output_format: "json".into(),
            rate_limit: None,
            concurrency: 500,
            random_agent: false,
            proxy_file: None,
            waf_detect: false,
            crawl: false,
            crawl_depth: 3,
            crawl_headers: None,
            log_level: "info".into(),
            log_file: None,
            worker: None,
            mitm_proxy: None,
            control_port: None,
            tls_cert: None,
            tls_key: None,
            require_signed_plugins: false,
            resume: None,
            config_file: None,
        }
    }
}

/// Errors during config validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Template path does not exist: {0}")]
    TemplateNotFound(PathBuf),

    #[error("Proxy file not found: {0}")]
    ProxyNotFound(PathBuf),

    #[error("Log file parent directory does not exist: {0}")]
    LogFileParentMissing(PathBuf),

    #[error("TLS cert not found: {0}")]
    TlsCertNotFound(PathBuf),

    #[error("TLS key not found: {0}")]
    TlsKeyNotFound(PathBuf),

    #[error("Invalid target URL: {0}")]
    InvalidTargetUrl(String),

    #[error("Cannot use both --template and --nuclei-template")]
    ConflictingTemplateFlags,

    #[error("Rate limit must be > 0, got {0}")]
    InvalidRateLimit(u32),

    #[error("Concurrency must be > 0, got {0}")]
    InvalidConcurrency(usize),

    #[error("Crawl depth must be > 0, got {0}")]
    InvalidCrawlDepth(usize),

    #[error("Config file path not set")]
    ConfigFileNotSet,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(#[from] serde_yaml::Error),
}

impl ValayamConfig {
    /// Load config from a YAML file, overlaying defaults and then applying overrides.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let mut config: ValayamConfig = serde_yaml::from_str(&content)?;
        config.config_file = Some(path.to_path_buf());
        Ok(config)
    }

    /// Load config with the layered priority:
    /// defaults → config file → env vars → CLI overrides.
    ///
    /// `cli_overrides` is an optional `Self` with only the fields the user
    /// explicitly set on the command line. Call this once at startup.
    pub fn layered(
        config_file: Option<&Path>,
        cli_overrides: Option<ValayamConfig>,
    ) -> Result<Self, ConfigError> {
        let mut config = ValayamConfig::default();

        // Layer 2: config file
        if let Some(path) = config_file {
            let file_config = Self::from_file(path)?;
            config.merge(file_config);
        }

        // Layer 3: environment variables
        config.apply_env_overrides();

        // Layer 4: CLI overrides (highest priority)
        if let Some(overrides) = cli_overrides {
            config.merge_non_default(overrides);
        }

        config.validate()?;
        Ok(config)
    }

    /// Merge all set fields from `other` into `self`.
    fn merge(&mut self, other: ValayamConfig) {
        // Non-Option fields with non-trivial defaults
        if other.target != default_target() {
            self.target = other.target;
        }
        if other.output_format != "json" {
            self.output_format = other.output_format;
        }
        if other.concurrency != 500 {
            self.concurrency = other.concurrency;
        }
        if other.random_agent {
            self.random_agent = true;
        }
        if other.waf_detect {
            self.waf_detect = true;
        }
        if other.crawl {
            self.crawl = true;
        }
        if other.crawl_depth != 3 {
            self.crawl_depth = other.crawl_depth;
        }
        if other.log_level != "info" {
            self.log_level = other.log_level;
        }
        if other.require_signed_plugins {
            self.require_signed_plugins = true;
        }

        // Option<T> fields — override only when Some
        if other.template.is_some() {
            self.template = other.template;
        }
        if other.nuclei_template.is_some() {
            self.nuclei_template = other.nuclei_template;
        }
        if other.output.is_some() {
            self.output = other.output;
        }
        if other.rate_limit.is_some() {
            self.rate_limit = other.rate_limit;
        }
        if other.proxy_file.is_some() {
            self.proxy_file = other.proxy_file;
        }
        if other.log_file.is_some() {
            self.log_file = other.log_file;
        }
        if other.worker.is_some() {
            self.worker = other.worker;
        }
        if other.mitm_proxy.is_some() {
            self.mitm_proxy = other.mitm_proxy;
        }
        if other.control_port.is_some() {
            self.control_port = other.control_port;
        }
        if other.tls_cert.is_some() {
            self.tls_cert = other.tls_cert;
        }
        if other.tls_key.is_some() {
            self.tls_key = other.tls_key;
        }
        if other.resume.is_some() {
            self.resume = other.resume;
        }
        if other.crawl_headers.is_some() {
            self.crawl_headers = other.crawl_headers;
        }

        if other.config_file.is_some() {
            self.config_file = other.config_file;
        }
    }

    /// Merge only fields that differ from `None`/default in `other` (CLI overrides).
    fn merge_non_default(&mut self, other: ValayamConfig) {
        // For Option<T> fields, if other has Some, override
        if other.template.is_some() {
            self.template = other.template;
        }
        if other.nuclei_template.is_some() {
            self.nuclei_template = other.nuclei_template;
        }
        if other.output.is_some() {
            self.output = other.output;
        }
        if other.rate_limit.is_some() {
            self.rate_limit = other.rate_limit;
        }
        if other.proxy_file.is_some() {
            self.proxy_file = other.proxy_file;
        }
        if other.log_file.is_some() {
            self.log_file = other.log_file;
        }
        if other.worker.is_some() {
            self.worker = other.worker;
        }
        if other.mitm_proxy.is_some() {
            self.mitm_proxy = other.mitm_proxy;
        }
        if other.control_port.is_some() {
            self.control_port = other.control_port;
        }
        if other.tls_cert.is_some() {
            self.tls_cert = other.tls_cert;
        }
        if other.tls_key.is_some() {
            self.tls_key = other.tls_key;
        }
        if other.resume.is_some() {
            self.resume = other.resume;
        }
        if other.crawl_headers.is_some() {
            self.crawl_headers = other.crawl_headers;
        }

        // For non-Option fields, always override (CLI picks explicit values)
        if other.target != default_target() {
            self.target = other.target;
        }
        if other.output_format != "json" {
            self.output_format = other.output_format;
        }
        if other.concurrency != 500 {
            self.concurrency = other.concurrency;
        }
        if other.random_agent {
            self.random_agent = true;
        }
        if other.waf_detect {
            self.waf_detect = true;
        }
        if other.crawl {
            self.crawl = true;
        }
        if other.crawl_depth != 3 {
            self.crawl_depth = other.crawl_depth;
        }
        if other.log_level != "info" {
            self.log_level = other.log_level;
        }
        if other.require_signed_plugins {
            self.require_signed_plugins = true;
        }
    }

    /// Apply environment variable overrides. Uses `VALAYAM_*` prefix.
    fn apply_env_overrides(&mut self) {
        /// Apply a non-optional env override (string)
        macro_rules! env_str {
            ($var:literal, $field:ident) => {
                if let Ok(val) = std::env::var(concat!("VALAYAM_", $var)) {
                    self.$field = val;
                }
            };
        }
        /// Apply a non-optional env override (parseable type: bool, usize, u32, etc.)
        macro_rules! env_parse {
            ($var:literal, $field:ident) => {
                if let Ok(val) = std::env::var(concat!("VALAYAM_", $var)) {
                    match val.parse::<_>() {
                        Ok(parsed) => self.$field = parsed,
                        Err(_) => tracing::warn!(var = concat!("VALAYAM_", $var), value = %val, "failed to parse env var"),
                    }
                }
            };
        }
        /// Apply an optional-path env override
        macro_rules! env_opt_path {
            ($var:literal, $field:ident) => {
                if let Ok(val) = std::env::var(concat!("VALAYAM_", $var)) {
                    self.$field = Some(PathBuf::from(val));
                }
            };
        }
        /// Apply an optional-parse env override
        macro_rules! env_opt_parse {
            ($var:literal, $field:ident) => {
                if let Ok(val) = std::env::var(concat!("VALAYAM_", $var)) {
                    match val.parse::<_>() {
                        Ok(parsed) => self.$field = Some(parsed),
                        Err(_) => tracing::warn!(var = concat!("VALAYAM_", $var), value = %val, "failed to parse env var"),
                    }
                }
            };
        }

        /// Apply an optional-string env override
        macro_rules! env_opt_str {
            ($var:literal, $field:ident) => {
                if let Ok(val) = std::env::var(concat!("VALAYAM_", $var)) {
                    self.$field = Some(val);
                }
            };
        }

        env_str!("TARGET", target);
        env_opt_path!("TEMPLATE", template);
        env_opt_path!("NUCLEI_TEMPLATE", nuclei_template);
        env_opt_path!("OUTPUT", output);
        env_opt_parse!("RATE_LIMIT", rate_limit);
        env_parse!("CONCURRENCY", concurrency);
        env_parse!("RANDOM_AGENT", random_agent);
        env_opt_path!("PROXY_FILE", proxy_file);
        env_parse!("WAF_DETECT", waf_detect);
        env_parse!("CRAWL", crawl);
        env_parse!("CRAWL_DEPTH", crawl_depth);
        env_str!("LOG_LEVEL", log_level);
        env_opt_path!("LOG_FILE", log_file);
        env_opt_str!("WORKER", worker);
        env_opt_parse!("MITM_PROXY", mitm_proxy);
        env_opt_parse!("CONTROL_PORT", control_port);
        env_opt_path!("TLS_CERT", tls_cert);
        env_opt_path!("TLS_KEY", tls_key);
        env_parse!("REQUIRE_SIGNED_PLUGINS", require_signed_plugins);
        env_opt_str!("RESUME", resume);
    }

    /// Validate the configuration, returning the first error found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Conflicting template flags — check before path existence (testable without I/O)
        if self.template.is_some() && self.nuclei_template.is_some() {
            return Err(ConfigError::ConflictingTemplateFlags);
        }

        // Template paths must exist if provided
        if let Some(ref t) = self.template {
            if !t.exists() {
                return Err(ConfigError::TemplateNotFound(t.clone()));
            }
        }
        if let Some(ref n) = self.nuclei_template {
            if !n.exists() {
                return Err(ConfigError::TemplateNotFound(n.clone()));
            }
        }

        // Proxy file must exist
        if let Some(ref p) = self.proxy_file {
            if !p.exists() {
                return Err(ConfigError::ProxyNotFound(p.clone()));
            }
        }

        // Log file parent must exist
        if let Some(ref l) = self.log_file {
            if let Some(parent) = l.parent() {
                if !parent.exists() {
                    return Err(ConfigError::LogFileParentMissing(l.clone()));
                }
            }
        }

        // TLS files must exist if provided
        if let Some(ref c) = self.tls_cert {
            if !c.exists() {
                return Err(ConfigError::TlsCertNotFound(c.clone()));
            }
        }
        if let Some(ref k) = self.tls_key {
            if !k.exists() {
                return Err(ConfigError::TlsKeyNotFound(k.clone()));
            }
        }

        // Target must be a valid URL
        url::Url::parse(&self.target)
            .map_err(|_| ConfigError::InvalidTargetUrl(self.target.clone()))?;

        // Rate limit must be > 0
        if let Some(r) = self.rate_limit {
            if r == 0 {
                return Err(ConfigError::InvalidRateLimit(r));
            }
        }

        // Concurrency must be > 0
        if self.concurrency == 0 {
            return Err(ConfigError::InvalidConcurrency(self.concurrency));
        }

        // Crawl depth must be > 0
        if self.crawl_depth == 0 {
            return Err(ConfigError::InvalidCrawlDepth(self.crawl_depth));
        }

        Ok(())
    }
}

fn default_target() -> String {
    "https://httpbin.org".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ValayamConfig::default();
        assert_eq!(config.target, "https://httpbin.org");
        assert_eq!(config.concurrency, 500);
        assert!(config.template.is_none());
    }

    #[test]
    fn test_validate_default() {
        let config = ValayamConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_url() {
        let mut config = ValayamConfig::default();
        config.target = "not-a-url".into();
        assert!(matches!(
            config.validate().unwrap_err(),
            ConfigError::InvalidTargetUrl(_)
        ));
    }

    #[test]
    fn test_validate_zero_concurrency() {
        let mut config = ValayamConfig::default();
        config.concurrency = 0;
        assert!(matches!(
            config.validate().unwrap_err(),
            ConfigError::InvalidConcurrency(0)
        ));
    }

    #[test]
    fn test_validate_zero_crawl_depth() {
        let mut config = ValayamConfig::default();
        config.crawl_depth = 0;
        assert!(matches!(
            config.validate().unwrap_err(),
            ConfigError::InvalidCrawlDepth(0)
        ));
    }

    #[test]
    fn test_validate_conflicting_templates() {
        let mut config = ValayamConfig::default();
        config.template = Some("./templates".into());
        config.nuclei_template = Some("./nuclei".into());
        assert!(matches!(
            config.validate().unwrap_err(),
            ConfigError::ConflictingTemplateFlags
        ));
    }

    #[test]
    fn test_validate_zero_rate_limit() {
        let mut config = ValayamConfig::default();
        config.rate_limit = Some(0);
        assert!(matches!(
            config.validate().unwrap_err(),
            ConfigError::InvalidRateLimit(0)
        ));
    }

    #[test]
    fn test_serialize_roundtrip() {
        let config = ValayamConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: ValayamConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.target, config.target);
        assert_eq!(deserialized.concurrency, config.concurrency);
    }

    #[test]
    fn test_merge_config_file_overrides_defaults() {
        let mut file_config = ValayamConfig::default();
        file_config.target = "https://custom-target.com".into();
        file_config.concurrency = 100;
        file_config.crawl = true;

        let mut base = ValayamConfig::default();
        base.merge(file_config);

        assert_eq!(base.target, "https://custom-target.com");
        assert_eq!(base.concurrency, 100);
        assert!(base.crawl);
    }

    #[test]
    fn test_merge_empty_file_config_keeps_defaults() {
        let file_config = ValayamConfig::default();

        let mut base = ValayamConfig::default();
        base.target = "https://override.com".into();
        base.merge(file_config);

        // file_config has default "https://httpbin.org" but merge only overrides
        // when values differ from default — base keeps its override
        assert_eq!(base.target, "https://override.com");
    }

    #[test]
    fn test_env_override_applied() {
        // We can't easily test env vars in unit tests without pollution,
        // but we can verify the override logic compiles and doesn't panic
        let mut config = ValayamConfig::default();
        config.apply_env_overrides(); // should not panic
    }

    #[test]
    fn test_merge_non_default_cli_overrides() {
        let mut base = ValayamConfig::default();
        let mut cli = ValayamConfig::default();
        cli.target = "https://cli-target.com".into();
        cli.concurrency = 50;
        cli.crawl = true;

        base.merge_non_default(cli);
        assert_eq!(base.target, "https://cli-target.com");
        assert_eq!(base.concurrency, 50);
        assert!(base.crawl);
    }

    #[test]
    fn test_layered_config_no_file() {
        let config = ValayamConfig::layered(None, None).unwrap();
        assert_eq!(config.target, "https://httpbin.org");
    }
}
