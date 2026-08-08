use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3AuditTemplate {
    pub rpc_endpoint: Option<String>,
    pub bytecode: Option<String>,
    pub action: String, // "fuzz_rpc" or "static_analyze"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_web3_audit_template_deser() {
        let json = r#"{"rpc_endpoint": "https://eth-mainnet.g.alchemy.com/v2/xxx", "bytecode": null, "action": "fuzz_rpc"}"#;
        let tmpl: Web3AuditTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(
            tmpl.rpc_endpoint,
            Some("https://eth-mainnet.g.alchemy.com/v2/xxx".into())
        );
        assert!(tmpl.bytecode.is_none());
        assert_eq!(tmpl.action, "fuzz_rpc");
    }

    #[test]
    fn test_web3_audit_variants() {
        let json =
            r#"{"rpc_endpoint": null, "bytecode": "0x60806040", "action": "static_analyze"}"#;
        let tmpl: Web3AuditTemplate = serde_json::from_str(json).unwrap();
        assert!(tmpl.rpc_endpoint.is_none());
        assert_eq!(tmpl.bytecode, Some("0x60806040".into()));
        assert_eq!(tmpl.action, "static_analyze");
    }

    #[test]
    fn test_web3_audit_serde_roundtrip() {
        let tmpl = Web3AuditTemplate {
            rpc_endpoint: Some("https://rpc.roundtrip.dev".into()),
            bytecode: None,
            action: "fuzz_rpc".into(),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: Web3AuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.rpc_endpoint, deser.rpc_endpoint);
        assert_eq!(tmpl.bytecode, deser.bytecode);
        assert_eq!(tmpl.action, deser.action);
    }
}
