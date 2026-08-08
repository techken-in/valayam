use std::collections::HashMap;

/// Maps vulnerabilities to standard compliance frameworks.
pub struct ComplianceMapper;

impl ComplianceMapper {
    /// Maps a given template tag (e.g., "sqli", "xss") to OWASP Top 10 and CWE.
    pub fn get_compliance_info(tags: &[String]) -> HashMap<&'static str, &'static str> {
        let mut info = HashMap::new();

        for tag in tags {
            match tag.as_str() {
                "sqli" => {
                    info.insert("OWASP", "A03:2021-Injection");
                    info.insert("CWE", "CWE-89");
                }
                "xss" => {
                    info.insert("OWASP", "A03:2021-Injection");
                    info.insert("CWE", "CWE-79");
                }
                "lfi" | "path-traversal" => {
                    info.insert("OWASP", "A01:2021-Broken Access Control");
                    info.insert("CWE", "CWE-22");
                }
                "ssrf" => {
                    info.insert("OWASP", "A10:2021-Server-Side Request Forgery");
                    info.insert("CWE", "CWE-918");
                }
                "rce" | "command-injection" => {
                    info.insert("OWASP", "A03:2021-Injection");
                    info.insert("CWE", "CWE-78");
                }
                "cve" => {
                    info.insert("OWASP", "A06:2021-Vulnerable and Outdated Components");
                }
                _ => {}
            }
        }

        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_mapping() {
        let tags = vec!["sqli".to_string()];
        let info = ComplianceMapper::get_compliance_info(&tags);
        assert_eq!(info.get("OWASP"), Some(&"A03:2021-Injection"));
        assert_eq!(info.get("CWE"), Some(&"CWE-89"));
    }

    #[test]
    fn test_xss_mapping() {
        let tags = vec!["xss".to_string()];
        let info = ComplianceMapper::get_compliance_info(&tags);
        assert_eq!(info.get("OWASP"), Some(&"A03:2021-Injection"));
        assert_eq!(info.get("CWE"), Some(&"CWE-79"));
    }

    #[test]
    fn test_unknown_tag_returns_empty() {
        let tags = vec!["unknown_tag".to_string()];
        let info = ComplianceMapper::get_compliance_info(&tags);
        assert!(info.is_empty());
    }

    #[test]
    fn test_multiple_tags_accumulates() {
        let tags = vec!["sqli".to_string(), "xss".to_string()];
        let info = ComplianceMapper::get_compliance_info(&tags);
        // CWE-89 overwritten by CWE-79 since both are under "CWE" key
        assert_eq!(info.len(), 2);
        assert_eq!(info.get("CWE"), Some(&"CWE-79"));
    }

    #[test]
    fn test_empty_tags() {
        let info = ComplianceMapper::get_compliance_info(&[]);
        assert!(info.is_empty());
    }
}
