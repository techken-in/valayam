//! Async-safe SARIF Reporter.
//!
//! Outputs vulnerability findings in the Static Analysis Results Interchange Format (SARIF).

use serde_json::json;
use std::fs::File;
use std::io::{self, BufWriter};
use std::sync::Mutex;
use valayam_engine::traits::{FindingOwned, Reporter};

pub struct SarifReporter {
    path: String,
    scanner_version: String,
    findings: Mutex<Vec<FindingOwned>>,
}

impl SarifReporter {
    pub fn new(path: String, scanner_version: String) -> io::Result<Self> {
        Ok(Self {
            path,
            scanner_version,
            findings: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl Reporter for SarifReporter {
    async fn process_finding(&self, finding: &FindingOwned) -> Result<(), std::io::Error> {
        let mut findings = self.findings.lock().unwrap();
        findings.push(finding.clone());
        Ok(())
    }
}

impl Drop for SarifReporter {
    fn drop(&mut self) {
        let findings = std::mem::take(&mut *self.findings.lock().unwrap());
        if findings.is_empty() {
            return; // Don't write empty SARIF
        }

        let rules: Vec<_> = findings
            .iter()
            .map(|f| {
                json!({
                    "id": f.template_id,
                    "name": f.template_name,
                    "shortDescription": {
                        "text": f.template_name
                    },
                    "fullDescription": {
                        "text": f.description.clone().unwrap_or_else(|| "".to_string())
                    },
                    "properties": {
                        "severity": f.severity.to_string(),
                        "solution": f.solution.clone().unwrap_or_else(|| "".to_string()),
                    }
                })
            })
            .collect();

        let results: Vec<_> = findings
            .iter()
            .map(|f| {
                let level = match f.severity {
                    valayam_models::finding::Severity::Critical
                    | valayam_models::finding::Severity::High => "error",
                    valayam_models::finding::Severity::Medium => "warning",
                    _ => "note",
                };

                json!({
                    "ruleId": f.template_id,
                    "level": level,
                    "message": {
                        "text": format!("Vulnerability found in {}", f.target)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.target
                            },
                            "region": {
                                "snippet": {
                                    "text": f.matched_at
                                }
                            }
                        }
                    }]
                })
            })
            .collect();

        let sarif_log = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Valayam Scanner",
                        "version": self.scanner_version,
                        "rules": rules
                    }
                },
                "results": results
            }]
        });

        let path = self.path.clone();

        let _ = std::thread::spawn(move || {
            if let Ok(file) = File::create(&path) {
                let writer = BufWriter::new(file);
                if let Err(e) = serde_json::to_writer_pretty(writer, &sarif_log) {
                    tracing::error!("Failed to write SARIF report: {}", e);
                }
            } else {
                tracing::error!("Failed to create SARIF report file: {}", path);
            }
        })
        .join();
    }
}
