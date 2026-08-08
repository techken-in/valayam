//! Bridge utility: convert between legacy ScanResult and FindingOwned.
//! After Phase 1 refactor, only the finding-to-scan direction is needed
//! (for legacy reporter compatibility). The scan-to-finding direction is
//! still needed in the gRPC wire-format deserialization path.

use crate::finding::FindingOwned;
use crate::result::ScanResult;
use std::collections::HashMap;

/// Prefix used for ScanResult-only fields stored in FindingOwned.metadata.
const META_CVSS_SCORE: &str = "::cvss_score";
const META_SOLUTION: &str = "::solution";
const META_REFERENCE: &str = "::reference";

/// Convert a legacy ScanResult into a FindingOwned.
///
/// Used by the gRPC deserialization path where ScanResult is still the wire format.
pub fn scan_result_to_finding(res: ScanResult) -> FindingOwned {
    let mut metadata = res.compliance;
    if let Some(cvss) = res.cvss_score {
        metadata.insert(META_CVSS_SCORE.to_string(), cvss.to_string());
    }
    if let Some(ref_) = res.reference {
        metadata.insert(META_REFERENCE.to_string(), ref_);
    }
    if let Some(sol) = res.solution {
        metadata.insert(META_SOLUTION.to_string(), sol);
    }
    if !res.tags.is_empty() {
        metadata.insert("::tags".to_string(), res.tags.join(","));
    }
    FindingOwned {
        scan_id: uuid::Uuid::default(),
        template_id: res.template_id,
        template_name: res.template_name,
        severity: std::str::FromStr::from_str(&res.template_severity)
            .unwrap_or(crate::finding::Severity::Unknown),
        target: res.target,
        matched_at: res.payload,
        description: None,
        solution: None,
        extracted_data: None,
        metadata,
    }
}

/// Reconstruct a ScanResult from a FindingOwned without data loss.
///
/// Extracts `cvss_score`, `solution`, `reference`, and `tags` from
/// `FindingOwned.metadata` where they were stored by the `from_template` constructor.
pub fn finding_to_scan_result(finding: FindingOwned) -> ScanResult {
    let mut compliance = HashMap::new();
    let mut cvss_score: Option<f32> = None;
    let mut solution: Option<String> = None;
    let mut reference: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();

    for (key, value) in &finding.metadata {
        match key.as_str() {
            META_CVSS_SCORE => {
                cvss_score = value.parse::<f32>().ok();
            }
            META_SOLUTION => {
                solution = Some(value.clone());
            }
            META_REFERENCE => {
                reference = Some(value.clone());
            }
            "::tags" => {
                tags = value.split(',').map(|s| s.to_string()).collect();
            }
            // Everything else is genuine compliance data
            other => {
                compliance.insert(other.to_string(), value.clone());
            }
        }
    }

    ScanResult {
        schema_version: "1.0.0".to_string(),
        timestamp: chrono::Utc::now(),
        template_id: finding.template_id,
        template_name: finding.template_name,
        template_severity: finding.severity.to_string(),
        target: finding.target,
        payload: finding.matched_at,
        compliance,
        cvss_score,
        solution: finding.solution.or(solution),
        reference,
        tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_to_scan_result_preserves_solution() {
        // solution in FindingOwned.solution should take precedence over metadata
        let finding = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test".into(),
            template_name: "Test".into(),
            severity: "info".into(),
            target: "https://example.com".into(),
            matched_at: "matched".into(),
            description: None,
            solution: Some("direct solution".into()),
            extracted_data: None,
            metadata: [("::solution".into(), "metadata solution".into())].into(),
        };

        let sr = finding_to_scan_result(finding);
        // FindingOwned.solution takes precedence via finding.solution.or(solution)
        assert_eq!(sr.solution.unwrap(), "direct solution");
    }

    #[test]
    fn test_finding_to_scan_result_cvss_from_metadata() {
        let finding = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test".into(),
            template_name: "Test".into(),
            severity: "high".into(),
            target: "https://example.com".into(),
            matched_at: "match".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: [("::cvss_score".into(), "5.5".into())].into(),
        };

        let sr = finding_to_scan_result(finding);
        assert_eq!(sr.cvss_score, Some(5.5));
    }

    #[test]
    fn test_finding_to_scan_result_with_compliance() {
        let finding = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "compliance-only".into(),
            template_name: "Compliance".into(),
            severity: "medium".into(),
            target: "https://test.com".into(),
            matched_at: "compliance issue".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: [
                ("owasp".into(), "A3:2017".into()),
                ("nist".into(), "SP-800-53".into()),
            ]
            .into(),
        };

        let back = finding_to_scan_result(finding);

        assert_eq!(back.compliance.get("owasp").unwrap(), "A3:2017");
        assert_eq!(back.compliance.get("nist").unwrap(), "SP-800-53");
        assert_eq!(back.compliance.len(), 2);
    }

    #[test]
    fn test_finding_to_scan_result_tags_from_metadata() {
        let finding = FindingOwned {
            scan_id: uuid::Uuid::default(),
            template_id: "test".into(),
            template_name: "Test".into(),
            severity: "high".into(),
            target: "https://example.com".into(),
            matched_at: "match".into(),
            description: None,
            solution: None,
            extracted_data: None,
            metadata: [("::tags".into(), "xss,sql".into())].into(),
        };

        let sr = finding_to_scan_result(finding);
        assert!(sr.tags.contains(&"xss".to_string()));
        assert!(sr.tags.contains(&"sql".to_string()));
    }
}
