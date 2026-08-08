//! Core trait definitions for the Valayam plugin architecture.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;

pub use valayam_models::finding::{FindingOwned, PluginHealth, PluginMetrics, PluginOutcomeKind};
pub use valayam_models::template_info::TemplateMetadata;
pub use valayam_models::ScanResult;
/// Documentation for this item.
pub const MINIMUM_API_VERSION: &str = "1.0";
// ─── VariableScope ──────────────────────────────────────────────────────

/// Namespaced variable context for template `{{placeholder}}` resolution.
#[derive(Debug, Clone, Default)]
pub struct VariableScope {
    global: std::collections::HashMap<String, String>,
    scoped: std::collections::HashMap<String, std::collections::HashMap<String, String>>,
}

impl VariableScope {
    /// Documentation for this item.
    pub fn new(globals: HashMap<String, String>) -> Self {
        Self {
            global: globals,
            scoped: HashMap::new(),
        }
    }
    /// Documentation for this item.
    pub fn set_global(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.global.insert(key.into(), value.into());
    }
    /// Documentation for this item.
    pub fn set(&mut self, plugin: &str, key: impl Into<String>, value: impl Into<String>) {
        self.scoped
            .entry(plugin.to_string())
            .or_default()
            .insert(key.into(), value.into());
    }
    /// Documentation for this item.
    pub fn get(&self, key: &str) -> Option<&String> {
        if let Some(v) = self.global.get(key) {
            return Some(v);
        }
        for scope in self.scoped.values() {
            if let Some(v) = scope.get(key) {
                return Some(v);
            }
        }
        None
    }
    /// Documentation for this item.
    pub fn to_flat_map(&self) -> std::collections::HashMap<String, String> {
        let mut flat = self.global.clone();
        for scope in self.scoped.values() {
            flat.extend(scope.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        flat
    }
    /// Documentation for this item.
    pub fn merge_from(&mut self, other: &VariableScope) {
        self.global.extend(other.global.clone());
        for (plugin, vars) in &other.scoped {
            self.scoped
                .entry(plugin.clone())
                .or_default()
                .extend(vars.clone());
        }
    }
}

// ─── ScanContext ────────────────────────────────────────────────────────

/// Typed execution context passed to every plugin.
///
/// All fields are behind `Arc`, `RwLock`, or owned `String` so the context
/// is safe to share across concurrent plugin executions and across `catch_unwind`
/// boundaries via `SafePluginFuture`.
pub struct ScanContext {
    /// Unique scan session identifier, propagated through the entire MPSC pipeline
    /// for audit trail and provenance tracking.
    pub scan_id: uuid::Uuid,
    /// Documentation for this item.
    pub target: String,
    /// Documentation for this item.
    pub target_host: String,
    /// Documentation for this item.
    pub template: Arc<valayam_models::templates::schema::VulnerabilityTemplate>, // Passed via Arc, no cloning!
    /// Documentation for this item.
    pub variables: Arc<RwLock<VariableScope>>,
    /// Documentation for this item.
    pub finding_tx: mpsc::Sender<FindingOwned>,
    /// Documentation for this item.
    pub cancellation: CancellationToken,
}

impl ScanContext {
    /// Documentation for this item.
    pub async fn snapshot_variables(&self) -> std::collections::HashMap<String, String> {
        self.variables.read().await.to_flat_map()
    }
    /// Documentation for this item.
    pub async fn set_variable(&self, plugin_name: &str, key: &str, value: String) {
        self.variables.write().await.set(plugin_name, key, value);
    }
    /// Documentation for this item.
    pub async fn emit_finding(
        &self,
        mut finding: FindingOwned,
    ) -> Result<(), mpsc::error::SendError<FindingOwned>> {
        // Auto-inject description if the plugin omitted it
        if finding.description.is_none() {
            finding.description = self.template.description().map(|s| s.to_string());
        }
        self.finding_tx.send(finding).await
    }
    /// Documentation for this item.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

// ─── PluginOutcome & Metrics ────────────────────────────────────────────

#[derive(Debug)]
/// Documentation for this item.
pub enum PluginOutcome {
    /// Documentation for this item.
    NoMatch,
    /// Documentation for this item.
    Matched {
        /// Number of matched vulnerabilities
        count: usize,
    },
    /// Documentation for this item.
    Skipped {
        /// Reason for skipping
        reason: String,
    },
    /// Documentation for this item.
    Failed {
        /// The error that occurred
        error: valayam_models::error::ScannerError,
        /// Whether the failure can be retried
        retryable: bool,
    },
}

// ─── ScanPlugin Trait (Enterprise Lifecycle) ────────────────────────────

/// A scan plugin with full lifecycle management.
/// No `RefUnwindSafe` bound needed here, handled at the call site.
#[async_trait::async_trait]
pub trait ScanPlugin: Send + Sync {
    /// Documentation for this item.
    fn name(&self) -> &str;
    /// Documentation for this item.
    fn version(&self) -> &str {
        "0.1.0"
    }
    /// Documentation for this item.
    fn api_version(&self) -> &str {
        "1.0"
    }

    /// Documentation for this item.
    fn is_applicable(
        &self,
        template: &valayam_models::templates::schema::VulnerabilityTemplate,
    ) -> bool;

    /// Validate the plugin's configuration against a template.
    fn validate_config(
        &self,
        _template: &valayam_models::templates::schema::VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError>;
    /// Documentation for this item.
    async fn init(&self) -> Result<(), valayam_models::error::ScannerError>;

    /// Execute the plugin's scan logic.
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome;

    /// Documentation for this item.
    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError>;

    /// Perform a health check. Returns `Ok(())` if healthy, or an error describing
    /// what is wrong. Called by `PluginRegistry::health_check_all()`.
    async fn health_check(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    /// Documentation for this item.
    fn depends_on(&self) -> &[&'static str] {
        &[]
    }
    /// Documentation for this item.
    fn timeout(&self) -> Duration {
        Duration::from_secs(60)
    }
}

// ─── Matcher Trait (zero-copy on &[u8]) ─────────────────────────────────

/// Evaluates a response buffer against matching rules.
/// Operates entirely on `&[u8]` byte slices — no allocations in the hot path.
pub trait Matcher: Send + Sync {
    /// Returns `true` if the response matches the vulnerability signature.
    fn evaluate(&self, response_buffer: &[u8]) -> bool;
    /// Human-readable name for diagnostics.
    fn name(&self) -> &str {
        "unnamed"
    }
}

// ─── Reporter Trait (async-safe) ────────────────────────────────────────

/// Processes and outputs findings. The Consumer in the MPSC architecture.
///
/// Uses `async_trait` because reporters may need async I/O (file writes,
/// network sends to SIEM). The consumer task calls this from an async context.
#[async_trait::async_trait]
pub trait Reporter: Send + Sync {
    /// Process a single finding.
    async fn process_finding(&self, finding: &FindingOwned) -> Result<(), std::io::Error>;

    /// Flush all buffered output. Called on shutdown.
    async fn flush(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FindingOwned tests ─────────────────────────────────────────────────

    #[test]
    fn test_finding_owned_dedup_key() {
        let f = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test-001".into(),
            template_name: "Test Finding".into(),
            severity: "high".into(),
            target: "https://example.com".into(),
            matched_at: "/login".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        };
        let key = f.dedup_key();
        assert_eq!(
            key,
            (
                "test-001".into(),
                "https://example.com".into(),
                "/login".into()
            )
        );
    }

    #[test]
    fn test_finding_owned_dedup_key_differentiates() {
        let f1 = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test-001".into(),
            target: "https://example.com".into(),
            matched_at: "/login".into(),
            ..default_finding()
        };
        let f2 = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test-002".into(),
            target: "https://example.com".into(),
            matched_at: "/login".into(),
            ..default_finding()
        };
        let f3 = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test-001".into(),
            target: "https://other.com".into(),
            matched_at: "/login".into(),
            ..default_finding()
        };
        assert_ne!(f1.dedup_key(), f2.dedup_key());
        assert_ne!(f1.dedup_key(), f3.dedup_key());
    }

    #[test]
    fn test_finding_owned_into_scan_result() {
        let f = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "cve-2024-1234".into(),
            template_name: "SQL Injection Test".into(),
            severity: "critical".into(),
            target: "https://target.com/login".into(),
            matched_at: "error in SQL parser".into(),
            description: Some("SQLi detected".into()),
            solution: Some("Use prepared statements".into()),
            extracted_data: Some("admin' OR 1=1".into()),
            metadata: [("cwe".into(), "89".into())].into(),
        };

        let sr = f.into_scan_result();
        assert_eq!(sr.template_id, "cve-2024-1234");
        assert_eq!(sr.template_name, "SQL Injection Test");
        assert_eq!(sr.template_severity, "critical");
        assert_eq!(sr.target, "https://target.com/login");
        assert_eq!(sr.payload, "error in SQL parser");
    }

    // ── VariableScope tests ────────────────────────────────────────────────

    #[test]
    fn test_variable_scope_new() -> anyhow::Result<()> {
        let mut globals = HashMap::new();
        globals.insert("BaseURL".into(), "https://example.com".into());
        let scope = VariableScope::new(globals);
        assert_eq!(
            scope.get("BaseURL").map(|s| s.as_str()),
            Some("https://example.com")
        );
        assert!(scope.get("missing").is_none());
        Ok(())
    }

    #[test]
    fn test_variable_scope_set_global() -> anyhow::Result<()> {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set_global("Hostname", "example.com");
        assert_eq!(
            scope.get("Hostname").map(|s| s.as_str()),
            Some("example.com")
        );
        Ok(())
    }

    #[test]
    fn test_variable_scope_set_scoped() -> anyhow::Result<()> {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set("http_plugin", "response_body", "data");
        assert_eq!(scope.get("response_body").map(|s| s.as_str()), Some("data"));
        Ok(())
    }

    #[test]
    fn test_variable_scope_global_takes_precedence() -> anyhow::Result<()> {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set_global("key", "global_val");
        scope.set("plugin_a", "key", "scoped_val");
        // Global takes priority since it's checked first
        assert_eq!(scope.get("key").map(|s| s.as_str()), Some("global_val"));
        Ok(())
    }

    #[test]
    fn test_variable_scope_scoped_isolation() -> anyhow::Result<()> {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set("plugin_a", "key_a", "value_a");
        scope.set("plugin_b", "key_b", "value_b");
        // Each key only exists in one scope, so get() returns the correct value
        // regardless of HashMap iteration order
        assert_eq!(scope.get("key_a").map(|s| s.as_str()), Some("value_a"));
        assert_eq!(scope.get("key_b").map(|s| s.as_str()), Some("value_b"));
        Ok(())
    }

    #[test]
    fn test_variable_scope_to_flat_map() -> anyhow::Result<()> {
        let mut scope = VariableScope::new(HashMap::new());
        scope.set_global("g1", "global1");
        scope.set("p1", "s1", "scoped1");
        let flat = scope.to_flat_map();
        assert_eq!(flat.get("g1").map(|s| s.as_str()), Some("global1"));
        assert_eq!(flat.get("s1").map(|s| s.as_str()), Some("scoped1"));
        Ok(())
    }

    #[test]
    fn test_variable_scope_merge_from() -> anyhow::Result<()> {
        let mut scope_a = VariableScope::new(HashMap::new());
        scope_a.set_global("key_a", "val_a");
        scope_a.set("p1", "key_b", "val_b");

        let mut scope_b = VariableScope::new(HashMap::new());
        scope_b.set_global("key_c", "val_c");
        scope_b.set("p1", "key_d", "val_d");

        scope_a.merge_from(&scope_b);
        assert_eq!(scope_a.get("key_a").map(|s| s.as_str()), Some("val_a"));
        assert_eq!(scope_a.get("key_c").map(|s| s.as_str()), Some("val_c"));
        assert_eq!(scope_a.get("key_d").map(|s| s.as_str()), Some("val_d"));
        Ok(())
    }

    #[test]
    fn test_variable_scope_merge_overwrites_global() -> anyhow::Result<()> {
        let mut scope_a = VariableScope::new(HashMap::new());
        scope_a.set_global("key", "old");

        let mut scope_b = VariableScope::new(HashMap::new());
        scope_b.set_global("key", "new");

        scope_a.merge_from(&scope_b);
        assert_eq!(scope_a.get("key").map(|s| s.as_str()), Some("new"));
        Ok(())
    }

    // ── ScanContext tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_scan_context_snapshot_variables() -> anyhow::Result<()> {
        let vars = Arc::new(RwLock::new(VariableScope::new({
            let mut m = HashMap::new();
            m.insert("BaseURL".into(), "https://example.com".into());
            m
        })));

        let ctx = ScanContext {
            scan_id: uuid::Uuid::default(),
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(valayam_models::templates::schema::VulnerabilityTemplate::default()),
            variables: vars,
            finding_tx: mpsc::channel(10).0,
            cancellation: CancellationToken::new(),
        };

        let snapshot = ctx.snapshot_variables().await;
        assert_eq!(
            snapshot.get("BaseURL").map(|s| s.as_str()),
            Some("https://example.com")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_scan_context_set_variable() -> anyhow::Result<()> {
        let vars = Arc::new(RwLock::new(VariableScope::new(HashMap::new())));
        let ctx = ScanContext {
            scan_id: uuid::Uuid::default(),
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(valayam_models::templates::schema::VulnerabilityTemplate::default()),
            variables: vars.clone(),
            finding_tx: mpsc::channel(10).0,
            cancellation: CancellationToken::new(),
        };

        ctx.set_variable("test_plugin", "extracted", "secret_value".to_string())
            .await;
        let snapshot = ctx.snapshot_variables().await;
        assert_eq!(
            snapshot.get("extracted").map(|s| s.as_str()),
            Some("secret_value")
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_scan_context_is_cancelled() {
        let token = CancellationToken::new();
        let ctx = ScanContext {
            scan_id: uuid::Uuid::default(),
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(valayam_models::templates::schema::VulnerabilityTemplate::default()),
            variables: Arc::new(RwLock::new(VariableScope::new(HashMap::new()))),
            finding_tx: mpsc::channel(10).0,
            cancellation: token.clone(),
        };
        assert!(!ctx.is_cancelled());
        token.cancel();
        assert!(ctx.is_cancelled());
    }

    #[tokio::test]
    async fn test_scan_context_emit_finding() -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::channel(10);
        let ctx = ScanContext {
            scan_id: uuid::Uuid::default(),
            target: "https://example.com".into(),
            target_host: "example.com".into(),
            template: Arc::new(valayam_models::templates::schema::VulnerabilityTemplate {
                id: "test".into(),
                info: valayam_models::templates::schema::TemplateInfo {
                    name: "Test".into(),
                    severity: "info".into(),
                    author: None,
                    description: Some("desc".into()),
                    tags: vec![],
                    compliance: Default::default(),
                },
                ..valayam_models::templates::schema::VulnerabilityTemplate::default()
            }),
            variables: Arc::new(RwLock::new(VariableScope::new(HashMap::new()))),
            finding_tx: tx,
            cancellation: CancellationToken::new(),
        };

        let finding = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test-001".into(),
            template_name: "Test".into(),
            severity: "info".into(),
            target: "https://example.com".into(),
            matched_at: "matched".into(),
            description: None, // Should be auto-injected
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        };

        ctx.emit_finding(finding).await?;
        let received = rx.recv().await.unwrap(); // MPSC channel recv is fine to unwrap in tests if we want, but better use ok_or
        assert_eq!(received.template_id, "test-001");
        // Description should be auto-injected from template
        assert_eq!(received.description.as_deref(), Some("desc"));
        Ok(())
    }

    // ── PluginOutcomeKind tests ────────────────────────────────────────────

    #[test]
    fn test_plugin_outcome_kind_display() {
        assert_eq!(PluginOutcomeKind::NoMatch.to_string(), "no_match");
        assert_eq!(PluginOutcomeKind::Matched.to_string(), "matched");
        assert_eq!(PluginOutcomeKind::Skipped.to_string(), "skipped");
        assert_eq!(PluginOutcomeKind::Failed.to_string(), "failed");
        assert_eq!(PluginOutcomeKind::TimedOut.to_string(), "timed_out");
        assert_eq!(PluginOutcomeKind::Crashed.to_string(), "crashed");
    }

    #[test]
    fn test_plugin_outcome_kind_serde_round_trip() -> anyhow::Result<()> {
        let cases = vec![
            PluginOutcomeKind::NoMatch,
            PluginOutcomeKind::Matched,
            PluginOutcomeKind::Failed,
            PluginOutcomeKind::Crashed,
        ];
        for kind in cases {
            let json = serde_json::to_string(&kind)?;
            let back: PluginOutcomeKind = serde_json::from_str(&json)?;
            assert_eq!(kind, back);
        }
        Ok(())
    }

    // ── PluginMetrics tests ────────────────────────────────────────────────

    #[test]
    fn test_plugin_metrics_serde() -> anyhow::Result<()> {
        let m = PluginMetrics {
            plugin_name: "http_scan".into(),
            target: "https://example.com".into(),
            outcome: PluginOutcomeKind::Matched,
            duration: Duration::from_millis(150),
            finding_count: 3,
        };
        let json = serde_json::to_string(&m)?;
        let back: PluginMetrics = serde_json::from_str(&json)?;
        assert_eq!(back.plugin_name, "http_scan");
        assert_eq!(back.outcome, PluginOutcomeKind::Matched);
        assert_eq!(back.finding_count, 3);
        assert_eq!(back.duration.as_millis(), 150);
        Ok(())
    }

    // ── PluginHealth tests ─────────────────────────────────────────────────

    #[test]
    fn test_plugin_health_healthy() {
        let h = PluginHealth {
            plugin_name: "test_plugin".into(),
            is_healthy: true,
            error: None,
            last_checked_ms: 42,
        };
        assert!(h.is_healthy);
        assert!(h.error.is_none());
    }

    #[test]
    fn test_plugin_health_unhealthy() -> anyhow::Result<()> {
        let h = PluginHealth {
            plugin_name: "broken_plugin".into(),
            is_healthy: false,
            error: Some("out of memory".into()),
            last_checked_ms: 7,
        };
        assert!(!h.is_healthy);
        assert_eq!(h.error.as_deref(), Some("out of memory"));
        Ok(())
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    fn default_finding() -> FindingOwned {
        FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: String::new(),
            template_name: String::new(),
            severity: valayam_models::finding::Severity::Unknown,
            target: String::new(),
            matched_at: String::new(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: HashMap::new(),
        }
    }
}
