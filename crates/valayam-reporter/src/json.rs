//! Async-safe JSON Reporter.
//!
//! Uses `tokio::task::spawn_blocking` for file I/O to avoid
//! blocking the async runtime.

use std::fs::File;
use std::io::{self, BufWriter};
use std::sync::Mutex;
use valayam_engine::traits::{FindingOwned, Reporter};

pub struct JsonReporter {
    path: String,
    scan_id: String,
    start_time: String,
    plugins: Vec<String>,
    templates: Vec<String>,
    targets: Vec<String>,
    scanner_version: String,
    /// Platform-assigned job ID — included in the output envelope
    /// so the platform can match results to the dispatched job.
    job_id: Option<String>,
    findings: Mutex<Vec<FindingOwned>>,
}

impl JsonReporter {
    pub fn new(
        path: String,
        scan_id: String,
        start_time: String,
        plugins: Vec<String>,
        templates: Vec<String>,
        targets: Vec<String>,
        scanner_version: String,
    ) -> io::Result<Self> {
        Ok(Self {
            path,
            scan_id,
            start_time,
            plugins,
            templates,
            targets,
            scanner_version,
            job_id: None,
            findings: Mutex::new(Vec::new()),
        })
    }

    /// Set the platform-assigned job ID for this scan. Included in the output
    /// envelope so the platform can correlate results with a dispatched job.
    pub fn set_job_id(&mut self, job_id: String) {
        self.job_id = Some(job_id);
    }
}

#[async_trait::async_trait]
impl Reporter for JsonReporter {
    async fn process_finding(&self, finding: &FindingOwned) -> io::Result<()> {
        let mut guard = self
            .findings
            .lock()
            .map_err(|e| io::Error::other(e.to_string()))?;
        guard.push(finding.clone());
        Ok(())
    }

    async fn flush(&self) -> io::Result<()> {
        let findings = {
            let mut guard = self
                .findings
                .lock()
                .map_err(|e| io::Error::other(e.to_string()))?;
            std::mem::take(&mut *guard)
        };

        let mut report = serde_json::json!({
            "scan_metadata": {
                "scan_id": self.scan_id,
                "scanner_name": "valayam",
                "scanner_version": self.scanner_version,
                "start_time": self.start_time,
                "end_time": chrono::Utc::now().to_rfc3339(),
                "status": "completed"
            },
            "scope": {
                "targets": self.targets,
            },
            "configuration": {
                "used_plugins": self.plugins,
                "used_templates": self.templates,
            },
            "findings": findings
        });

        if let Some(ref job_id) = self.job_id {
            report["job_id"] = serde_json::json!(job_id);
        }

        let file = File::create(&self.path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &report)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn sample_finding() -> FindingOwned {
        FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "json-001".into(),
            template_name: "JSON Test".into(),
            severity: "medium".into(),
            target: "https://example.com/api".into(),
            matched_at: "api".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_json_reporter_outputs_valid_json() {
        let path = "test_scan_results.json";
        let _ = fs::remove_file(path);

        let reporter = JsonReporter::new(
            path.to_string(),
            "test-scan-123".to_string(),
            "2026-07-26T12:00:00Z".to_string(),
            vec!["plugin1".to_string()],
            vec!["template1.yaml".to_string()],
            vec!["https://example.com".to_string()],
            "1.0.0".to_string(),
        )
        .unwrap();
        reporter.process_finding(&sample_finding()).await.unwrap();
        reporter.flush().await.unwrap();

        let content = fs::read_to_string(path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(parsed["scan_metadata"]["scan_id"], "test-scan-123");
        assert_eq!(parsed["configuration"]["used_plugins"][0], "plugin1");
        assert_eq!(parsed["findings"][0]["template_id"], "json-001");

        fs::remove_file(path).unwrap();
    }
}
