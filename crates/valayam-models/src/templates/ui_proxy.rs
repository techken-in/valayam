use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiProxyTemplate {
    pub enabled: bool,
    pub port: Option<u16>,
    pub allow_modification: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ui_proxy_template_deser() {
        let json = r#"{"enabled": true, "port": 8080, "allow_modification": false}"#;
        let tmpl: UiProxyTemplate = serde_json::from_str(json).unwrap();
        assert!(tmpl.enabled);
        assert_eq!(tmpl.port, Some(8080));
        assert_eq!(tmpl.allow_modification, Some(false));
    }

    #[test]
    fn test_ui_proxy_variants() {
        let json = r#"{"enabled": false, "port": null, "allow_modification": null}"#;
        let tmpl: UiProxyTemplate = serde_json::from_str(json).unwrap();
        assert!(!tmpl.enabled);
        assert!(tmpl.port.is_none());
        assert!(tmpl.allow_modification.is_none());
    }

    #[test]
    fn test_ui_proxy_serde_roundtrip() {
        let tmpl = UiProxyTemplate {
            enabled: true,
            port: Some(9090),
            allow_modification: Some(true),
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let deser: UiProxyTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(tmpl.enabled, deser.enabled);
        assert_eq!(tmpl.port, deser.port);
        assert_eq!(tmpl.allow_modification, deser.allow_modification);
    }
}
