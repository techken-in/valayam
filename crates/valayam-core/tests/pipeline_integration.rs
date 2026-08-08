mod common;

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use valayam_core::core::plugins::HttpScanPlugin;
use valayam_core::template::schema::VulnerabilityTemplate;
use valayam_engine::executor::ScanExecutor;
use valayam_engine::registry::PluginRegistry;
use valayam_engine::traits::ScanPlugin;

#[test]
fn test_pipeline_executor_constructs_and_cancels() {
    let http_client = common::build_http_client();
    let yaml = common::sample_template();
    let template = VulnerabilityTemplate::load_from_str(&yaml).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (tx, mut rx) = mpsc::channel(100);
        let registry = {
            let reg = PluginRegistry::new();
            reg.register(HttpScanPlugin::new(http_client));
            Arc::new(reg)
        };

        // Cancel before execution
        let cancel = CancellationToken::new();
        cancel.cancel();

        let executor = ScanExecutor::new(tx, registry, None, cancel);
        let metrics = executor
            .execute("https://nonexistent.local", Arc::new(template))
            .await;
        drop(executor);

        let mut findings = Vec::new();
        while let Ok(f) = rx.try_recv() {
            findings.push(f);
        }

        let total: usize = metrics.iter().map(|m| m.finding_count).sum();
        assert_eq!(
            total, 0,
            "Expected 0 findings with pre-cancellation, got {}",
            total
        );
    });
}

#[test]
fn test_pipeline_executor_without_cancellation() {
    let http_client = common::build_http_client();
    let yaml = common::sample_template();
    let template = VulnerabilityTemplate::load_from_str(&yaml).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (tx, mut rx) = mpsc::channel(100);
        let registry = {
            let reg = PluginRegistry::new();
            reg.register(HttpScanPlugin::new(http_client));
            Arc::new(reg)
        };

        let executor = ScanExecutor::new(tx, registry, None, CancellationToken::new());
        let _metrics = executor
            .execute("https://nonexistent.local", Arc::new(template))
            .await;
        drop(executor);

        let mut findings = Vec::new();
        while let Ok(f) = rx.try_recv() {
            findings.push(f);
        }

        // With no matching server, likely 0 findings. Just verify executor didn't panic
        // and channel wiring works (no findings ≠ broken pipeline).
        assert!(
            findings.is_empty(),
            "No findings expected against nonexistent target"
        );
    });
}

#[test]
fn test_template_parsing_and_registry() {
    let yaml = common::sample_template();
    let template = VulnerabilityTemplate::load_from_str(&yaml).unwrap();
    assert_eq!(template.id, "integ-ping-test");
    assert_eq!(template.info.name, "Ping Test");
    assert_eq!(template.info.severity, "info");
    assert!(
        !template.requests.is_empty(),
        "Template should have requests"
    );

    let http_client = common::build_http_client();
    let plugin = HttpScanPlugin::new(http_client);
    assert!(plugin.is_applicable(&template));
    assert_eq!(plugin.name(), "http_scan");
}
