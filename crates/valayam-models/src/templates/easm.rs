use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EasmTemplate {
    /// List of OSINT sources to query, e.g. ["crtsh", "alienvault"]
    pub sources: Vec<String>,

    /// Target domain to enumerate subdomains for. Usually "{{Hostname}}" or a literal domain.
    pub domain: String,

    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

fn default_max_results() -> usize {
    1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_easm_template_deser() {
        let json =
            r#"{"sources": ["crtsh", "alienvault"], "domain": "example.com", "max_results": 500}"#;
        let tmpl: EasmTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.sources, vec!["crtsh", "alienvault"]);
        assert_eq!(tmpl.domain, "example.com");
        assert_eq!(tmpl.max_results, 500);
    }

    #[test]
    fn test_easm_variants() {
        let json = r#"{"sources": ["shodan"], "domain": "test.org", "max_results": 100}"#;
        let tmpl: EasmTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tmpl.sources, vec!["shodan"]);
        assert_eq!(tmpl.domain, "test.org");
        assert_eq!(tmpl.max_results, 100);
    }

    #[test]
    fn test_easm_serde_roundtrip() {
        let tmpl = EasmTemplate {
            sources: vec!["crtsh".into()],
            domain: "roundtrip.dev".into(),
            max_results: 2000,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: EasmTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.sources, deser.sources);
        assert_eq!(tmpl.domain, deser.domain);
        assert_eq!(tmpl.max_results, deser.max_results);
    }
}
