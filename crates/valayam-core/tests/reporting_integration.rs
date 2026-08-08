mod common;

use tempfile::NamedTempFile;
use valayam_core::core::reporters::composite::CompositeReporter;
use valayam_core::core::reporters::console::ConsoleReporter;
use valayam_core::core::reporters::json::JsonReporter;
use valayam_engine::traits::FindingOwned;
use valayam_engine::traits::Reporter;

/// Helper to create multiple sample findings for reporter tests.
fn sample_findings() -> Vec<FindingOwned> {
    let mut f1 = common::sample_finding();
    f1.template_id = "report-test-001".into();

    let mut f2 = common::sample_finding();
    f2.template_id = "report-test-002".into();
    f2.severity = "critical".into();
    f2.target = "https://critical.example.com".into();
    f2.matched_at = "/admin".into();

    let mut f3 = common::sample_finding();
    f3.template_id = "report-test-003".into();
    f3.severity = "medium".into();

    vec![f1, f2, f3]
}

fn create_json_reporter(path: String) -> JsonReporter {
    JsonReporter::new(
        path,
        "test-scan-id".into(),
        "2026-07-26T12:00:00Z".into(),
        vec!["plugin1".into()],
        vec!["template1.yaml".into()],
        vec!["https://example.com".into()],
        "1.0.0".into(),
    )
    .unwrap()
}

#[tokio::test]
async fn test_json_reporter_output() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let reporter = create_json_reporter(path.clone());
    let findings = sample_findings();

    for f in &findings {
        reporter.process_finding(f).await.unwrap();
    }
    reporter.flush().await.unwrap();

    // Read back and verify
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(parsed["scan_metadata"]["scan_id"], "test-scan-id");
    let findings_arr = parsed["findings"].as_array().unwrap();
    assert_eq!(findings_arr.len(), 3, "Expected 3 findings");

    for (i, parsed_f) in findings_arr.iter().enumerate() {
        assert_eq!(parsed_f["template_id"], format!("report-test-{:03}", i + 1));
        assert!(parsed_f["severity"].is_string());
        assert!(parsed_f["target"].is_string());
        assert!(parsed_f["matched_at"].is_string());
    }
}

#[tokio::test]
async fn test_json_reporter_empty_findings() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let reporter = create_json_reporter(path.clone());
    reporter.flush().await.unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_console_reporter_processes_multiple() {
    let reporter = ConsoleReporter::default();
    let findings = sample_findings();

    for f in &findings {
        let result = reporter.process_finding(f).await;
        assert!(result.is_ok(), "Console reporter should not fail");
    }
    let result = reporter.flush().await;
    assert!(result.is_ok(), "Console flush should succeed");
}

#[tokio::test]
async fn test_composite_reporter() {
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let json_reporter = create_json_reporter(path.clone());
    let console_reporter = ConsoleReporter::default();
    let composite =
        CompositeReporter::new(vec![Box::new(json_reporter), Box::new(console_reporter)]);

    let findings = sample_findings();
    for f in &findings {
        composite.process_finding(f).await.unwrap();
    }
    composite.flush().await.unwrap();

    // Verify JSON file was written through composite
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        parsed["findings"].as_array().unwrap().len(),
        3,
        "Composite should delegate to JSON reporter"
    );
}
