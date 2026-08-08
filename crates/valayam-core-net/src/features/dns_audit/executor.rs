use regex::Regex;
use std::collections::HashMap;
use valayam_engine::variables::resolve_variables;
use valayam_models::finding::FindingOwned;
use valayam_models::templates::dns_audit::DnsRequestTemplate;
use valayam_models::TemplateMetadata;
use valayam_network::network::dns;

/// Executes all DNS audit rules from a template.
/// Performs DNS lookups and evaluates regex matchers against the results.
pub async fn execute(
    dns_rules: &[DnsRequestTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
    variables: &HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    for rule in dns_rules {
        let domain = resolve_variables(&rule.domain, variables).unwrap();

        tracing::debug!(target = %domain, query_type = %rule.query_type, "Starting DNS resolution");

        // 1. Basic resolution based on template query_type
        let records = match dns::resolve(&domain, &rule.query_type).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(target = %domain, error = %e, "DNS resolution failed");
                vec![]
            }
        };

        if !records.is_empty() {
            tracing::trace!(target = %domain, records_count = %records.len(), "DNS records resolved successfully");
            let records_text = records.join("\n");

            if rule.matchers.is_empty() {
                findings.push(FindingOwned::from_template_and_info(
                    template_id,
                    template_meta,
                    domain.clone(),
                    format!("{} records: {}", rule.query_type, records_text),
                ));
            } else {
                for matcher in &rule.matchers {
                    if matcher.r#type == "regex" {
                        for pattern in &matcher.regex {
                            let Ok(re) = Regex::new(pattern) else {
                                continue;
                            };
                            if re.is_match(&records_text) {
                                tracing::debug!(target = %domain, pattern = %pattern, "Vulnerability DNS match found");
                                findings.push(FindingOwned::from_template_and_info(
                                    template_id,
                                    template_meta,
                                    domain.clone(),
                                    format!(
                                        "DNS {} matched '{}': {}",
                                        rule.query_type, pattern, records_text
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // 2. Subdomain Takeover Probing
        let takeovers = dns::check_subdomain_takeover(&domain).await;
        for takeover in takeovers {
            findings.push(FindingOwned::from_template_and_info(
                template_id,
                template_meta,
                domain.clone(),
                format!(
                    "Subdomain Takeover vulnerability ({}) - CNAME {} points to unclaimed service {} ({}). Remediation: {}",
                    takeover.confidence, takeover.cname, takeover.service, takeover.target, takeover.remediation
                ),
            ));
        }

        // 3. DNS Rebinding Detection (Heuristic)
        // Perform two quick A record queries. If it shifts from a public IP to a local/private IP, flag it.
        if let Ok(first_a) = dns::resolve(&domain, "A").await {
            if let Some(first_ip) = first_a.first() {
                if !is_private_ip(first_ip) {
                    // Try second resolution
                    if let Ok(second_a) = dns::resolve(&domain, "A").await {
                        if let Some(second_ip) = second_a.first() {
                            if is_private_ip(second_ip) {
                                findings.push(FindingOwned::from_template_and_info(
                                    template_id,
                                    template_meta,
                                    domain.clone(),
                                    format!("DNS Rebinding vulnerability detected: IP shifted from {} to private IP {}", first_ip, second_ip),
                                ));
                            }
                        }
                    }
                }
            }
        }

        // 4. AXFR Zone Transfer Probes
        let axfr_records = dns::attempt_axfr(&domain, None).await;
        if !axfr_records.is_empty() {
            findings.push(FindingOwned::from_template_and_info(
                template_id,
                template_meta,
                domain.clone(),
                format!(
                    "Zone transfer (AXFR) successful! Recovered {} records.",
                    axfr_records.len()
                ),
            ));
        }
    }

    findings
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip.starts_with("192.168.")
        || ip.starts_with("10.")
        || (ip.starts_with("172.") && {
            // Crude check for 172.16.x.x - 172.31.x.x
            if let Some(second_octet) = ip.split('.').nth(1).and_then(|s| s.parse::<u8>().ok()) {
                (16..=31).contains(&second_octet)
            } else {
                false
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DnsRequestTemplate deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dns_template_minimal() {
        let yaml = r#"
domain: example.com
query_type: A
"#;
        let tmpl: DnsRequestTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.domain, "example.com");
        assert_eq!(tmpl.query_type, "A");
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_dns_template_with_matchers() {
        let yaml = r#"
domain: example.com
query_type: TXT
matchers:
  - type: regex
    part: body
    regex: ["spf"]
"#;
        let tmpl: DnsRequestTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.domain, "example.com");
        assert_eq!(tmpl.query_type, "TXT");
        assert_eq!(tmpl.matchers.len(), 1);
        assert_eq!(tmpl.matchers[0].regex[0], "spf");
    }

    #[test]
    fn test_dns_template_serde_roundtrip() {
        let tmpl = DnsRequestTemplate {
            domain: "test.com".to_string(),
            query_type: "MX".to_string(),
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: DnsRequestTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.domain, "test.com");
        assert_eq!(back.query_type, "MX");
    }

    // -----------------------------------------------------------------------
    // Variable resolution tests (the resolve step in execute)
    // -----------------------------------------------------------------------

    #[test]
    fn test_domain_variable_resolution() {
        let mut variables = HashMap::new();
        variables.insert("domain".to_string(), "example.com".to_string());
        let resolved = resolve_variables("{{domain}}", &variables).unwrap();
        assert_eq!(resolved, "example.com");
    }

    #[test]
    fn test_domain_variable_resolution_no_variable() {
        let variables = HashMap::new();
        let resolved = resolve_variables("example.com", &variables).unwrap();
        assert_eq!(resolved, "example.com");
    }

    // -----------------------------------------------------------------------
    // DNS records regex matching logic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_regex_matches_dns_records() {
        let records = vec![
            "10 mail.example.com".to_string(),
            "20 backup.example.com".to_string(),
        ];
        let records_text = records.join("\n");

        let re = Regex::new(r"mail\.example\.com").unwrap();
        assert!(re.is_match(&records_text));
    }

    #[test]
    fn test_regex_no_match_on_dns_records() {
        let records = vec!["10 mail.example.com".to_string()];
        let records_text = records.join("\n");

        let re = Regex::new(r"evil\.com").unwrap();
        assert!(!re.is_match(&records_text));
    }

    #[test]
    fn test_regex_match_spf_record() {
        let records = vec!["v=spf1 include:_spf.example.com ~all".to_string()];
        let records_text = records.join("\n");

        let re = Regex::new(r"v=spf1").unwrap();
        assert!(re.is_match(&records_text));
    }

    #[test]
    fn test_regex_match_cname_record() {
        let records = vec!["app.example.com.".to_string()];
        let records_text = records.join("\n");

        let re = Regex::new(r"example\.com").unwrap();
        assert!(re.is_match(&records_text));
    }
}
