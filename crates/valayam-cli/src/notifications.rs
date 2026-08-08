use reqwest::Client;
use serde_json::json;
use valayam_core::core::result::ScanResult;

/// Sends real-time notifications to webhooks (Slack, Teams, Discord).
pub struct Notifier;

impl Notifier {
    /// Send an alert to a Slack webhook for high-severity findings.
    pub async fn send_slack_alert(webhook_url: &str, result: &ScanResult) -> Result<(), String> {
        let client = Client::new();
        let payload = json!({
            "text": format!("🚨 *Vulnerability Found!*\n*Target:* {}\n*Template:* {}\n*Severity:* {}",
                            result.target, result.template_name, result.template_severity)
        });

        client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use valayam_core::core::result::ScanResult;

    #[test]
    fn test_slack_payload_format() {
        let result = ScanResult {
            template_id: "test-001".into(),
            template_name: "SQL Injection Test".into(),
            template_severity: "high".into(),
            target: "https://example.com/login".into(),
            payload: "detected".into(),
            ..Default::default()
        };

        let payload = serde_json::json!({
            "text": format!("🚨 *Vulnerability Found!*\n*Target:* {}\n*Template:* {}\n*Severity:* {}",
                            result.target, result.template_name, result.template_severity)
        });

        assert_eq!(
            payload["text"]
                .as_str()
                .unwrap()
                .contains("SQL Injection Test"),
            true
        );
        assert_eq!(
            payload["text"]
                .as_str()
                .unwrap()
                .contains("https://example.com/login"),
            true
        );
        assert_eq!(payload["text"].as_str().unwrap().contains("high"), true);
    }

    #[test]
    fn test_slack_payload_critical() {
        let result = ScanResult {
            template_name: "RCE".into(),
            template_severity: "critical".into(),
            target: "https://target.com".into(),
            ..Default::default()
        };

        let text = format!(
            "🚨 *Vulnerability Found!*\n*Target:* {}\n*Template:* {}\n*Severity:* {}",
            result.target, result.template_name, result.template_severity
        );

        assert!(text.contains("RCE"));
        assert!(text.contains("critical"));
        assert!(text.contains("🚨"));
    }
}
