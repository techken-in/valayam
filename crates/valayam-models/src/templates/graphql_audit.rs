use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GraphqlAuditTemplate {
    pub target: String,
    pub introspection: bool,
    pub mutate: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_template_deser() {
        let json = r#"{"target": "https://api.example.com/graphql", "introspection": true, "mutate": false}"#;
        let tmpl: GraphqlAuditTemplate = serde_json::from_str(json).unwrap();
        assert!(tmpl.introspection);
        assert!(!tmpl.mutate);
    }

    #[test]
    fn test_graphql_template_full_mutate() {
        let json = r#"{"target": "https://api.example.com/graphql", "introspection": false, "mutate": true}"#;
        let tmpl: GraphqlAuditTemplate = serde_json::from_str(json).unwrap();
        assert!(!tmpl.introspection);
        assert!(tmpl.mutate);
    }

    #[test]
    fn test_graphql_serde_roundtrip() {
        let tmpl = GraphqlAuditTemplate {
            target: "https://graphql.com".into(),
            introspection: true,
            mutate: true,
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: GraphqlAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target, "https://graphql.com");
        assert!(back.introspection);
    }
}
