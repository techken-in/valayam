//! ScanExecutor — the Producer in the MPSC architecture.
//!
//! Agnostic to what scans exist and how findings are logged.

use crate::rate_limiter::RateLimiter;
use crate::registry::PluginRegistry;
use crate::traits::{FindingOwned, PluginMetrics};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use valayam_models::templates::schema::VulnerabilityTemplate;

use crate::scan_state::ScanState;

#[derive(Clone)]
/// Documentation for this item.
pub struct ScanExecutor {
    finding_tx: mpsc::Sender<FindingOwned>,
    registry: Arc<PluginRegistry>,
    rate_limiter: Option<Arc<RateLimiter>>,
    cancellation: CancellationToken,
    state_rx: Option<tokio::sync::watch::Receiver<ScanState>>,
}

impl ScanExecutor {
    /// Documentation for this item.
    pub fn new(
        finding_tx: mpsc::Sender<FindingOwned>,
        registry: Arc<PluginRegistry>,
        rate_limiter: Option<Arc<RateLimiter>>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            finding_tx,
            registry,
            rate_limiter,
            cancellation,
            state_rx: None,
        }
    }

    /// Documentation for this item.
    pub fn with_state_rx(mut self, rx: tokio::sync::watch::Receiver<ScanState>) -> Self {
        self.state_rx = Some(rx);
        self
    }

    /// Execute a template against a target. Returns per-plugin metrics.
    pub async fn execute(
        &self,
        target: &str,
        template: Arc<VulnerabilityTemplate>,
    ) -> Vec<PluginMetrics> {
        if let Some(mut rx) = self.state_rx.clone() {
            let current_state = *rx.borrow();
            if current_state == ScanState::Paused {
                tracing::info!("Scan is paused, waiting to resume...");
                let _ = rx.wait_for(|s| *s == ScanState::Running).await;
                tracing::info!("Scan resumed.");
            }
        }

        self.registry
            .execute_template(
                target,
                template,
                &self.finding_tx,
                self.rate_limiter.as_deref(),
                self.cancellation.clone(),
            )
            .await
    }

    /// Access the underlying registry (for testing/inspection).
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    /// Access the rate limiter reference (if set).
    pub fn rate_limiter_ref(&self) -> Option<&Arc<RateLimiter>> {
        self.rate_limiter.as_ref()
    }

    /// Access the cancellation token (for testing).
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Access the finding sender (for testing).
    pub fn finding_tx(&self) -> &mpsc::Sender<FindingOwned> {
        &self.finding_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PluginRegistry;
    use crate::traits::{PluginOutcome, ScanContext, ScanPlugin};
    use valayam_models::templates::schema::{TemplateInfo, VulnerabilityTemplate};

    struct MockPlugin;

    #[async_trait::async_trait]
    impl ScanPlugin for MockPlugin {
        fn name(&self) -> &str {
            "mock"
        }
        fn is_applicable(&self, _: &VulnerabilityTemplate) -> bool {
            true
        }
        fn validate_config(
            &self,
            _: &valayam_models::templates::schema::VulnerabilityTemplate,
        ) -> Result<(), valayam_models::error::ScannerError> {
            Ok(())
        }
        async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
            Ok(())
        }
        async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
            let _ = ctx
                .finding_tx
                .send(FindingOwned {
                    scan_id: uuid::Uuid::default(),
                    template_id: "mock-001".into(),
                    template_name: "Mock".into(),
                    severity: "info".into(),
                    target: ctx.target.clone(),
                    matched_at: "test".into(),
                    description: None,
                    solution: None,
                    extracted_data: None,
                    metadata: Default::default(),
                })
                .await;
            PluginOutcome::Matched { count: 1 }
        }
    }

    fn dummy_template() -> Arc<VulnerabilityTemplate> {
        Arc::new(VulnerabilityTemplate {
            id: "test".into(),
            info: TemplateInfo {
                name: "Test".into(),
                severity: "info".into(),
                author: None,
                description: None,
                tags: vec![],
                compliance: Default::default(),
            },
            ..VulnerabilityTemplate::default()
        })
    }

    #[test]
    fn test_executor_new() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel.clone());

        // Verify accessor methods
        assert!(executor.rate_limiter_ref().is_none());
        assert!(!executor.cancellation_token().is_cancelled());
        cancel.cancel();
        assert!(executor.cancellation_token().is_cancelled());
    }

    #[test]
    fn test_executor_new_with_rate_limiter() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        let cancel = CancellationToken::new();
        let rl = Arc::new(crate::rate_limiter::RateLimiter::new_simple(100));
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), Some(rl.clone()), cancel);

        assert!(executor.rate_limiter_ref().is_some());
    }

    #[tokio::test]
    async fn test_executor_execute_delegates_to_registry() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        registry.register(MockPlugin);
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel.clone());

        let metrics = executor
            .execute("https://example.com", dummy_template())
            .await;
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].plugin_name, "mock");
        assert_eq!(
            metrics[0].outcome,
            crate::traits::PluginOutcomeKind::Matched
        );
    }

    #[tokio::test]
    async fn test_executor_cancellation_propagation() {
        let (tx, _rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        registry.register(MockPlugin);
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel.clone());

        assert!(!executor.cancellation_token().is_cancelled());
        cancel.cancel();
        assert!(executor.cancellation_token().is_cancelled());

        // Template still executes (cancellation is per-plugin, checked by individual plugins)
        let metrics = executor
            .execute("https://example.com", dummy_template())
            .await;
        assert_eq!(metrics.len(), 1);
    }

    #[tokio::test]
    async fn test_executor_finding_channel_wiring() {
        let (tx, mut rx) = mpsc::channel(10);
        let registry = Arc::new(PluginRegistry::new());
        registry.register(MockPlugin);
        let cancel = CancellationToken::new();
        let executor = ScanExecutor::new(tx.clone(), registry.clone(), None, cancel);

        executor
            .execute("https://example.com", dummy_template())
            .await;
        let received = rx.try_recv();
        assert!(received.is_ok());
        let finding = received.unwrap();
        assert_eq!(finding.template_id, "mock-001");
    }
}
