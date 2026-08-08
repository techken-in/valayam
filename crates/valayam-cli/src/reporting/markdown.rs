use std::fs::File;
use std::io::Write;
use valayam_core::core::result::ScanResult;

/// Generates a Markdown report from scan results.
pub struct MarkdownReporter;

impl MarkdownReporter {
    pub fn generate(results: &[ScanResult], output_path: &str) -> Result<(), String> {
        let mut md = String::from("# Valayam Vulnerability Scan Report\n\n");
        md.push_str("| Timestamp | Template | Severity | Target | Payload |\n");
        md.push_str("| --- | --- | --- | --- | --- |\n");

        for result in results {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                result.timestamp,
                result.template_name,
                result.template_severity,
                result.target,
                result.payload
            ));
        }

        let mut file = File::create(output_path).map_err(|e| e.to_string())?;
        file.write_all(md.as_bytes()).map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use valayam_core::core::result::ScanResult;

    fn sample_results() -> Vec<ScanResult> {
        vec![ScanResult {
            template_id: "test-001".into(),
            template_name: "SQLi Test".into(),
            template_severity: "high".into(),
            target: "https://example.com".into(),
            payload: "' OR 1=1".into(),
            ..Default::default()
        }]
    }

    #[test]
    fn test_markdown_generates_output() {
        let results = sample_results();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.md");
        let path_str = path.to_str().unwrap();

        MarkdownReporter::generate(&results, path_str).unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(path_str).unwrap();
        assert!(content.contains("Valayam Vulnerability Scan Report"));
        assert!(content.contains("SQLi Test"));
        assert!(content.contains("high"));
        assert!(content.contains("| Timestamp | Template | Severity | Target | Payload |"));
    }

    #[test]
    fn test_markdown_empty_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.md");
        let path_str = path.to_str().unwrap();

        MarkdownReporter::generate(&[], path_str).unwrap();
        let content = std::fs::read_to_string(path_str).unwrap();
        assert!(content.contains("Valayam Vulnerability Scan Report"));
        // Only header row exists — no data rows with "| "
        // Should have title, blank, header row, separator row — no data rows
        assert!(content.contains("Valayam Vulnerability Scan Report"));
        // No data rows contain '| |' pattern (empty pipe fields from missing results)
        let pipe_count = content.matches('|').count();
        // Header + separator: 12 pipes (6 per row × 2 rows)
        assert_eq!(
            pipe_count, 12,
            "Should be exactly 12 pipes in header+separator: {:?}",
            content
        );
    }

    #[test]
    fn test_markdown_invalid_path_returns_err() {
        let result = MarkdownReporter::generate(&sample_results(), "/nonexistent_dir/report.md");
        assert!(result.is_err());
    }
}
