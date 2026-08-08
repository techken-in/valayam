use colored::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use valayam_engine::traits::{FindingOwned, Reporter};

/// Console reporter that renders vulnerability findings as visually rich,
/// boxed cards with severity badges, timestamps, and optional metadata.
pub struct ConsoleReporter {
    finding_counter: AtomicUsize,
}

impl Default for ConsoleReporter {
    fn default() -> Self {
        Self {
            finding_counter: AtomicUsize::new(0),
        }
    }
}

impl ConsoleReporter {
    /// Returns a colored severity badge string with emoji prefix.
    fn severity_badge(severity: valayam_models::finding::Severity) -> ColoredString {
        use valayam_models::finding::Severity::*;
        match severity {
            Critical => " CRITICAL ".on_bright_magenta().white().bold(),
            High => " HIGH ".on_red().white().bold(),
            Medium => " MEDIUM ".on_yellow().black().bold(),
            Low => " LOW ".on_green().white().bold(),
            Info => " INFO ".on_blue().white().bold(),
            Unknown => " UNKNOWN ".normal().dimmed(),
        }
    }

    /// Returns the severity emoji prefix.
    fn severity_icon(severity: valayam_models::finding::Severity) -> &'static str {
        use valayam_models::finding::Severity::*;
        match severity {
            Critical => "💀",
            High => "🔴",
            Medium => "🟡",
            Low => "🟢",
            Info => "🔵",
            Unknown => "⚪",
        }
    }

    /// Truncates a string to `max_len` chars, appending `…` if truncated.
    fn truncate(s: &str, max_len: usize) -> String {
        if s.chars().count() <= max_len {
            s.to_string()
        } else {
            let truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
            format!("{}…", truncated)
        }
    }
}

#[async_trait::async_trait]
impl Reporter for ConsoleReporter {
    async fn process_finding(&self, finding: &FindingOwned) -> Result<(), std::io::Error> {
        let num = self.finding_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let icon = Self::severity_icon(finding.severity);
        let badge = Self::severity_badge(finding.severity);
        let width = 64;
        let bar = "─".repeat(width);

        println!();
        println!("  {}", format!("┌{}┐", bar).bright_black());

        println!(
            "  {}  {} {} {}",
            "│".bright_black(),
            icon,
            badge,
            finding.template_name.white().bold()
        );

        println!("  {}", format!("├{}┤", bar).bright_black());

        println!(
            "  {}  {}  {}",
            "│".bright_black(),
            format!("#{}", num).bright_black().bold(),
            finding.template_id.bright_black().italic()
        );

        println!(
            "  {}  {}   {}",
            "│".bright_black(),
            "Target:".bright_black(),
            finding.target.cyan()
        );

        let matched_display = Self::truncate(&finding.matched_at, 120);
        println!(
            "  {}  {}    {}",
            "│".bright_black(),
            "Match:".bright_black(),
            matched_display.bright_white()
        );

        if let Some(ref desc) = finding.description {
            let desc_display = Self::truncate(desc, 100);
            println!(
                "  {}  {}     {}",
                "│".bright_black(),
                "Desc:".bright_black(),
                desc_display.italic()
            );
        }

        if let Some(ref data) = finding.extracted_data {
            let data_display = Self::truncate(data, 100);
            println!(
                "  {}  {}     {}",
                "│".bright_black(),
                "Data:".bright_black(),
                data_display.green()
            );
        }

        if let Some(ref sol) = finding.solution {
            let sol_display = Self::truncate(sol, 100);
            println!(
                "  {}  {} {}",
                "│".bright_black(),
                "Solution:".bright_black(),
                sol_display.bright_green()
            );
        }

        println!("  {}", format!("└{}┘", bar).bright_black());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> FindingOwned {
        FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test-001".into(),
            template_name: "Test Finding".into(),
            severity: "high".into(),
            target: "https://example.com".into(),
            matched_at: "/login".into(),
            description: Some("SQL Injection detected".into()),
            solution: Some("Use prepared statements".into()),
            extracted_data: Some("admin' OR 1=1".into()),
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_console_reporter_process_finding() {
        let reporter = ConsoleReporter::default();
        let finding = sample_finding();
        let result = reporter.process_finding(&finding).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_console_reporter_multiple_findings() {
        let reporter = ConsoleReporter::default();
        let f1 = sample_finding();
        let f2 = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test-002".into(),
            template_name: "Low Severity".into(),
            severity: "low".into(),
            target: "https://other.com".into(),
            matched_at: "/public".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: Default::default(),
        };

        assert!(reporter.process_finding(&f1).await.is_ok());
        assert!(reporter.process_finding(&f2).await.is_ok());
    }

    #[tokio::test]
    async fn test_console_reporter_flush() {
        let reporter = ConsoleReporter::default();
        let result = reporter.flush().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_severity_badge_renders() {
        let critical =
            ConsoleReporter::severity_badge(valayam_models::finding::Severity::from("critical"));
        assert!(!critical.to_string().is_empty());

        let high = ConsoleReporter::severity_badge(valayam_models::finding::Severity::from("high"));
        assert!(!high.to_string().is_empty());

        let unknown =
            ConsoleReporter::severity_badge(valayam_models::finding::Severity::from("unknown"));
        assert!(!unknown.to_string().is_empty());
    }

    #[test]
    fn test_severity_icon_returns_expected() {
        assert_eq!(
            ConsoleReporter::severity_icon(valayam_models::finding::Severity::from("critical")),
            "💀"
        );
        assert_eq!(
            ConsoleReporter::severity_icon(valayam_models::finding::Severity::from("high")),
            "🔴"
        );
        assert_eq!(
            ConsoleReporter::severity_icon(valayam_models::finding::Severity::from("medium")),
            "🟡"
        );
        assert_eq!(
            ConsoleReporter::severity_icon(valayam_models::finding::Severity::from("low")),
            "🟢"
        );
        assert_eq!(
            ConsoleReporter::severity_icon(valayam_models::finding::Severity::from("info")),
            "🔵"
        );
        assert_eq!(
            ConsoleReporter::severity_icon(valayam_models::finding::Severity::from("unknown")),
            "⚪"
        );
    }

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(ConsoleReporter::truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let long = "a".repeat(100);
        let truncated = ConsoleReporter::truncate(&long, 10);
        assert_eq!(truncated.chars().count(), 10);
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn test_truncate_edge_cases() {
        assert_eq!(ConsoleReporter::truncate("", 10), "");
        assert_eq!(ConsoleReporter::truncate("abc", 0), "…");
    }
}
