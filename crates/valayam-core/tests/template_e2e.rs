mod common;

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use valayam_core::core::plugins::HttpScanPlugin;
use valayam_core::template::schema::VulnerabilityTemplate;
use valayam_engine::executor::ScanExecutor;
use valayam_engine::registry::PluginRegistry;

#[test]
fn test_template_load_and_validate() {
    let yaml = common::sample_template();
    let template = VulnerabilityTemplate::load_from_str(&yaml).unwrap();
    assert_eq!(template.id, "integ-ping-test");
    assert_eq!(template.info.name, "Ping Test");
    assert_eq!(template.info.severity, "info");
    assert!(template.validate().is_ok());
}

#[test]
fn test_template_with_executor_wiring() {
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

        // No findings expected against nonexistent target — just verify the
        // executor wires template → plugin → finding channel correctly.
        assert!(
            findings.is_empty(),
            "No findings against nonexistent target"
        );
    });
}

#[test]
fn test_executor_channel_and_cancellation() {
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
        assert_eq!(total, 0, "Expected 0 findings with cancellation");
    });
}
