use std::fs::File;
use std::io::Write;
use valayam_core::core::result::ScanResult;

/// Generates an HTML report from scan results.
pub struct HtmlReporter;

impl HtmlReporter {
    pub fn generate(results: &[ScanResult], output_path: &str) -> Result<(), String> {
        let mut html = String::from("<html><head><title>Valayam Scan Report</title></head><body>");
        html.push_str("<h1>Valayam Vulnerability Scan Report</h1>");
        html.push_str("<table border='1'><tr><th>Timestamp</th><th>Template</th><th>Severity</th><th>Target</th><th>Payload</th></tr>");

        for result in results {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                result.timestamp,
                result.template_name,
                result.template_severity,
                result.target,
                result.payload
            ));
        }

        html.push_str("</table></body></html>");

        let mut file = File::create(output_path).map_err(|e| e.to_string())?;
        file.write_all(html.as_bytes()).map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use valayam_core::core::result::ScanResult;

    fn sample_results() -> Vec<ScanResult> {
        vec![
            ScanResult {
                template_id: "test-001".into(),
                template_name: "SQLi Test".into(),
                template_severity: "high".into(),
                target: "https://example.com".into(),
                payload: "' OR 1=1".into(),
                ..Default::default()
            },
            ScanResult {
                template_id: "test-002".into(),
                template_name: "XSS Test".into(),
                template_severity: "medium".into(),
                target: "https://example.com".into(),
                payload: "<script>".into(),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn test_html_generates_output() {
        let results = sample_results();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.html");
        let path_str = path.to_str().unwrap();

        HtmlReporter::generate(&results, path_str).unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(path_str).unwrap();
        assert!(content.contains("Valayam Vulnerability Scan Report"));
        assert!(content.contains("SQLi Test"));
        assert!(content.contains("XSS Test"));
        assert!(content.contains("high"));
        assert!(content.contains("medium"));
        assert!(content.contains("<table"));
        assert!(content.contains("</table>"));
    }

    #[test]
    fn test_html_empty_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.html");
        let path_str = path.to_str().unwrap();

        HtmlReporter::generate(&[], path_str).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(path_str).unwrap();
        assert!(content.contains("<table"));
        assert!(content.contains("</table>"));
        // No rows besides header
        assert_eq!(content.matches("<tr>").count(), 1);
    }

    #[test]
    fn test_html_invalid_path_returns_err() {
        let results = sample_results();
        let result = HtmlReporter::generate(&results, "/nonexistent_dir/report.html");
        assert!(result.is_err());
    }
}
