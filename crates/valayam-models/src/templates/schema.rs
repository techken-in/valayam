use crate::templates::auth_logic::{AuthTemplate, LogicTemplate};
use crate::templates::auto_exploit::AutoExploitTemplate;
use crate::templates::auto_redteam::AutoRedteamTemplate;
use crate::templates::aws_escalate::AwsEscalateTemplate;
use crate::templates::azure_gcp_escalate::AzureGcpEscalateTemplate;
use crate::templates::browser_audit::BrowserAuditTemplate;
use crate::templates::cicd_audit::CicdAuditTemplate;
use crate::templates::client_secret_audit::ClientSecretAuditTemplate;
use crate::templates::cloud_sec::CloudTemplate;
use crate::templates::container_audit::ContainerAuditTemplate;
use crate::templates::cors_audit::CorsAuditTemplate;
use crate::templates::cred_monitor::CredMonitorTemplate;
use crate::templates::csp_audit::CspAuditTemplate;
use crate::templates::ct_log_audit::CtLogAuditTemplate;
use crate::templates::deep_analysis::DeepAnalysisTemplate;
use crate::templates::dependency_audit::DependencyAuditTemplate;
use crate::templates::dns_audit::DnsRequestTemplate;
use crate::templates::dom_redirect_audit::DomRedirectAuditTemplate;
use crate::templates::drift_detect::DriftDetectTemplate;
use crate::templates::easm::EasmTemplate;
use crate::templates::fuzzer::FuzzTemplate;
use crate::templates::graphql_audit::GraphqlAuditTemplate;
use crate::templates::grpc_audit::GrpcAuditTemplate;
use crate::templates::header_scorecard::HeaderScorecardTemplate;
use crate::templates::http_scan::HttpRequestTemplate;
use crate::templates::iac_audit::IacAuditTemplate;
use crate::templates::idp_audit::IdpAuditTemplate;
use crate::templates::implant_deploy::ImplantDeployTemplate;
use crate::templates::iot_audit::IotAuditTemplate;
use crate::templates::k8s_audit::K8sAuditTemplate;
use crate::templates::mitre_mapping::MitreMappingTemplate;
use crate::templates::mobile_audit::MobileAuditTemplate;
use crate::templates::network_scan::NetworkRequestTemplate;
use crate::templates::oauth_audit::OauthAuditTemplate;
use crate::templates::pii_leak_audit::PiiLeakAuditTemplate;
use crate::templates::port_scan::PortScanTemplate;
use crate::templates::remediation_gen::RemediationGenTemplate;
use crate::templates::reputation_audit::ReputationAuditTemplate;
use crate::templates::sast_secrets::SastSecretsTemplate;
use crate::templates::sast_taint::SastTaintTemplate;
use crate::templates::sbom_audit::SbomAuditTemplate;
use crate::templates::scada_audit::ScadaAuditTemplate;
use crate::templates::schema_drift::SchemaDriftTemplate;
use crate::templates::scripting::ScriptTemplate;
use crate::templates::section::TemplateSection;
use crate::templates::serverless_audit::ServerlessAuditTemplate;
use crate::templates::subdomain_takeover::SubdomainTakeoverTemplate;
use crate::templates::tls_audit::TlsAuditTemplate;
use crate::templates::ui_proxy::UiProxyTemplate;
use crate::templates::waf_bypass_verify::WafBypassVerifyTemplate;
use crate::templates::web3_audit::Web3AuditTemplate;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level template structure that composes types from all feature slices.
/// This is the single entry point for YAML deserialization of native templates.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub auth: Option<AuthTemplate>,
    #[serde(default)]
    pub requests: Vec<HttpRequestTemplate>,
    #[serde(default)]
    pub network: Vec<NetworkRequestTemplate>,
    #[serde(default)]
    pub scripts: Vec<ScriptTemplate>,
    #[serde(default)]
    pub dns: Vec<DnsRequestTemplate>,
    #[serde(default)]
    pub tls: Vec<TlsAuditTemplate>,
    #[serde(default)]
    pub fuzz: Vec<FuzzTemplate>,
    #[serde(default)]
    pub cloud: Vec<CloudTemplate>,
    #[serde(default)]
    pub logic: Vec<LogicTemplate>,
    #[serde(default)]
    pub deep_analysis: Vec<DeepAnalysisTemplate>,
    #[serde(default)]
    pub iac_audit: Vec<IacAuditTemplate>,
    #[serde(default)]
    pub sbom_audit: Vec<SbomAuditTemplate>,
    #[serde(default)]
    pub grpc_audit: Vec<GrpcAuditTemplate>,
    #[serde(default)]
    pub graphql_audit: Vec<GraphqlAuditTemplate>,
    #[serde(default)]
    pub drift_detect: Vec<DriftDetectTemplate>,
    #[serde(default)]
    pub cred_monitor: Vec<CredMonitorTemplate>,
    #[serde(default)]
    pub oauth_audit: Vec<OauthAuditTemplate>,
    #[serde(default)]
    pub idp_audit: Vec<IdpAuditTemplate>,
    #[serde(default)]
    pub aws_escalate: Vec<AwsEscalateTemplate>,
    #[serde(default)]
    pub azure_gcp_escalate: Vec<AzureGcpEscalateTemplate>,
    #[serde(default)]
    pub browser_audit: Vec<BrowserAuditTemplate>,
    #[serde(default)]
    pub iot_audit: Vec<IotAuditTemplate>,
    #[serde(default)]
    pub scada_audit: Vec<ScadaAuditTemplate>,
    #[serde(default)]
    pub auto_redteam: Vec<AutoRedteamTemplate>,
    #[serde(default)]
    pub implant_deploy: Vec<ImplantDeployTemplate>,
    #[serde(default)]
    pub client_secret_audit: Vec<ClientSecretAuditTemplate>,
    #[serde(default)]
    pub dom_redirect_audit: Vec<DomRedirectAuditTemplate>,
    #[serde(default)]
    pub cors_audit: Vec<CorsAuditTemplate>,
    #[serde(default)]
    pub csp_audit: Vec<CspAuditTemplate>,
    #[serde(default)]
    pub waf_bypass_verify: Vec<WafBypassVerifyTemplate>,
    #[serde(default)]
    pub header_scorecard: Vec<HeaderScorecardTemplate>,
    #[serde(default)]
    pub reputation_audit: Vec<ReputationAuditTemplate>,
    #[serde(default)]
    pub ct_log_audit: Vec<CtLogAuditTemplate>,
    #[serde(default)]
    pub remediation_gen: Vec<RemediationGenTemplate>,
    #[serde(default)]
    pub mitre_mapping: Vec<MitreMappingTemplate>,
    #[serde(default)]
    pub container_audit: Vec<ContainerAuditTemplate>,
    #[serde(default)]
    pub k8s_audit: Vec<K8sAuditTemplate>,
    #[serde(default)]
    pub sast_taint: Vec<SastTaintTemplate>,
    #[serde(default)]
    pub sast_secrets: Vec<SastSecretsTemplate>,
    #[serde(default)]
    pub subdomain_takeover: Vec<SubdomainTakeoverTemplate>,
    #[serde(default)]
    pub port_scan: Vec<PortScanTemplate>,
    #[serde(default)]
    pub schema_drift: Vec<SchemaDriftTemplate>,
    #[serde(default)]
    pub pii_leak_audit: Vec<PiiLeakAuditTemplate>,
    #[serde(default)]
    pub cicd_audit: Vec<CicdAuditTemplate>,
    #[serde(default)]
    pub dependency_audit: Vec<DependencyAuditTemplate>,
    #[serde(default)]
    pub easm: Vec<EasmTemplate>,
    #[serde(default)]
    pub web3_audit: Vec<Web3AuditTemplate>,
    #[serde(default)]
    pub mobile_audit: Vec<MobileAuditTemplate>,
    #[serde(default)]
    pub serverless_audit: Vec<ServerlessAuditTemplate>,
    #[serde(default)]
    pub auto_exploit: Vec<AutoExploitTemplate>,
    #[serde(default)]
    pub ui_proxy: Vec<UiProxyTemplate>,
    #[serde(default)]
    pub oob_interaction: bool,
}

pub use crate::template_info::TemplateInfo;
pub use crate::template_info::TemplateMetadata;

impl TemplateMetadata for VulnerabilityTemplate {
    fn template_name(&self) -> &str {
        &self.info.name
    }
    fn template_severity(&self) -> &str {
        &self.info.severity
    }
    fn description(&self) -> Option<&str> {
        self.info.description.as_deref()
    }
    fn author(&self) -> Option<&str> {
        self.info.author.as_deref()
    }
    fn tags(&self) -> &[String] {
        &self.info.tags
    }
    fn compliance(&self) -> &std::collections::HashMap<String, String> {
        &self.info.compliance
    }
}

impl VulnerabilityTemplate {
    pub fn empty() -> Self {
        Self {
            id: String::new(),
            info: TemplateInfo {
                name: String::new(),
                severity: "info".into(),
                author: None,
                description: None,
                tags: vec![],
                compliance: Default::default(),
            },
            auth: None,
            requests: vec![],
            network: vec![],
            scripts: vec![],
            dns: vec![],
            tls: vec![],
            fuzz: vec![],
            cloud: vec![],
            logic: vec![],
            deep_analysis: vec![],
            iac_audit: vec![],
            sbom_audit: vec![],
            grpc_audit: vec![],
            graphql_audit: vec![],
            drift_detect: vec![],
            cred_monitor: vec![],
            oauth_audit: vec![],
            idp_audit: vec![],
            aws_escalate: vec![],
            azure_gcp_escalate: vec![],
            browser_audit: vec![],
            iot_audit: vec![],
            scada_audit: vec![],
            auto_redteam: vec![],
            implant_deploy: vec![],
            client_secret_audit: vec![],
            dom_redirect_audit: vec![],
            cors_audit: vec![],
            csp_audit: vec![],
            waf_bypass_verify: vec![],
            header_scorecard: vec![],
            reputation_audit: vec![],
            ct_log_audit: vec![],
            remediation_gen: vec![],
            mitre_mapping: vec![],
            container_audit: vec![],
            k8s_audit: vec![],
            sast_taint: vec![],
            sast_secrets: vec![],
            subdomain_takeover: vec![],
            port_scan: vec![],
            schema_drift: vec![],
            pii_leak_audit: vec![],
            cicd_audit: vec![],
            dependency_audit: vec![],
            easm: vec![],
            web3_audit: vec![],
            mobile_audit: vec![],
            serverless_audit: vec![],
            auto_exploit: vec![],
            ui_proxy: vec![],
            oob_interaction: false,
        }
    }

    /// Iterate all non-empty template sections as trait objects.
    ///
    /// Enables trait-based plugin dispatch: plugins check applicability by
    /// calling `template.has_section(plugin_section_name)` instead of matching
    /// on individual fields.
    pub fn sections(&self) -> Vec<&dyn super::section::TemplateSection> {
        let mut s: Vec<&dyn super::section::TemplateSection> = Vec::new();
        if let Some(ref a) = self.auth {
            s.push(a);
        }
        for r in &self.requests {
            s.push(r as &dyn TemplateSection);
        }
        for n in &self.network {
            s.push(n as &dyn TemplateSection);
        }
        for r in &self.scripts {
            s.push(r as &dyn TemplateSection);
        }
        for d in &self.dns {
            s.push(d as &dyn TemplateSection);
        }
        for t in &self.tls {
            s.push(t as &dyn TemplateSection);
        }
        for f in &self.fuzz {
            s.push(f as &dyn TemplateSection);
        }
        for c in &self.cloud {
            s.push(c as &dyn TemplateSection);
        }
        for l in &self.logic {
            s.push(l as &dyn TemplateSection);
        }
        for d in &self.deep_analysis {
            s.push(d as &dyn TemplateSection);
        }
        for i in &self.iac_audit {
            s.push(i as &dyn TemplateSection);
        }
        for s_ in &self.sbom_audit {
            s.push(s_ as &dyn TemplateSection);
        }
        for g in &self.grpc_audit {
            s.push(g as &dyn TemplateSection);
        }
        for g in &self.graphql_audit {
            s.push(g as &dyn TemplateSection);
        }
        for d in &self.drift_detect {
            s.push(d as &dyn TemplateSection);
        }
        for c in &self.cred_monitor {
            s.push(c as &dyn TemplateSection);
        }
        for o in &self.oauth_audit {
            s.push(o as &dyn TemplateSection);
        }
        for i in &self.idp_audit {
            s.push(i as &dyn TemplateSection);
        }
        for a in &self.aws_escalate {
            s.push(a as &dyn TemplateSection);
        }
        for a in &self.azure_gcp_escalate {
            s.push(a as &dyn TemplateSection);
        }
        for b in &self.browser_audit {
            s.push(b as &dyn TemplateSection);
        }
        for i in &self.iot_audit {
            s.push(i as &dyn TemplateSection);
        }
        for s_ in &self.scada_audit {
            s.push(s_ as &dyn TemplateSection);
        }
        for a in &self.auto_redteam {
            s.push(a as &dyn TemplateSection);
        }
        for i in &self.implant_deploy {
            s.push(i as &dyn TemplateSection);
        }
        for c in &self.client_secret_audit {
            s.push(c as &dyn TemplateSection);
        }
        for d in &self.dom_redirect_audit {
            s.push(d as &dyn TemplateSection);
        }
        for c in &self.cors_audit {
            s.push(c as &dyn TemplateSection);
        }
        for c in &self.csp_audit {
            s.push(c as &dyn TemplateSection);
        }
        for w in &self.waf_bypass_verify {
            s.push(w as &dyn TemplateSection);
        }
        for h in &self.header_scorecard {
            s.push(h as &dyn TemplateSection);
        }
        for r in &self.reputation_audit {
            s.push(r as &dyn TemplateSection);
        }
        for c in &self.ct_log_audit {
            s.push(c as &dyn TemplateSection);
        }
        for r in &self.remediation_gen {
            s.push(r as &dyn TemplateSection);
        }
        for m in &self.mitre_mapping {
            s.push(m as &dyn TemplateSection);
        }
        for c in &self.container_audit {
            s.push(c as &dyn TemplateSection);
        }
        for k in &self.k8s_audit {
            s.push(k as &dyn TemplateSection);
        }
        for s_ in &self.sast_taint {
            s.push(s_ as &dyn TemplateSection);
        }
        for s_ in &self.sast_secrets {
            s.push(s_ as &dyn TemplateSection);
        }
        for s_ in &self.subdomain_takeover {
            s.push(s_ as &dyn TemplateSection);
        }
        for p in &self.port_scan {
            s.push(p as &dyn TemplateSection);
        }
        for s_ in &self.schema_drift {
            s.push(s_ as &dyn TemplateSection);
        }
        for p in &self.pii_leak_audit {
            s.push(p as &dyn TemplateSection);
        }
        for c in &self.cicd_audit {
            s.push(c as &dyn TemplateSection);
        }
        for d in &self.dependency_audit {
            s.push(d as &dyn TemplateSection);
        }
        for e in &self.easm {
            s.push(e as &dyn TemplateSection);
        }
        for w in &self.web3_audit {
            s.push(w as &dyn TemplateSection);
        }
        for m in &self.mobile_audit {
            s.push(m as &dyn TemplateSection);
        }
        for s_ in &self.serverless_audit {
            s.push(s_ as &dyn TemplateSection);
        }
        for a in &self.auto_exploit {
            s.push(a as &dyn TemplateSection);
        }
        for u in &self.ui_proxy {
            s.push(u as &dyn TemplateSection);
        }
        s
    }

    /// Check if this template has a section matching `name` (kebab-case, as
    /// defined by the section's `TemplateSection::section_name()`).
    pub fn has_section(&self, name: &str) -> bool {
        self.sections().iter().any(|s| s.section_name() == name)
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, crate::error::ScannerError> {
        let content = std::fs::read_to_string(path)?;
        Self::load_from_str(&content)
    }

    pub fn load_from_str(content: &str) -> Result<Self, crate::error::ScannerError> {
        // Detect and convert OpenAPI/Swagger JSON specifications dynamically
        // OpenAPI/Swagger detected — would convert to template in future
        let _is_openapi = content.trim().starts_with('{')
            && (content.contains("\"openapi\"") || content.contains("\"swagger\""));

        let template: VulnerabilityTemplate = serde_yaml::from_str(content)?;
        template.validate()?;
        Ok(template)
    }

    /// Validate the template for required fields and consistency.
    /// Returns an error with a description of what is invalid.
    pub fn validate(&self) -> Result<(), crate::error::ScannerError> {
        use crate::error::ScannerError;

        if self.id.trim().is_empty() {
            return Err(ScannerError::TemplateValidationError(
                "template id must not be empty".to_string(),
            ));
        }

        if self.info.name.trim().is_empty() {
            return Err(ScannerError::TemplateValidationError(
                "template info.name must not be empty".to_string(),
            ));
        }

        // Validate severity is a recognized value
        let valid_severities = ["info", "low", "medium", "high", "critical"];
        let sev = self.info.severity.to_lowercase();
        if !sev.is_empty() && !valid_severities.contains(&sev.as_str()) {
            return Err(ScannerError::TemplateValidationError(format!(
                "invalid severity '{}'. Must be one of: {:?}",
                self.info.severity, valid_severities
            )));
        }

        // At least one section must be defined (uses trait-based check)
        let has_any_definition = !self.sections().is_empty() || self.oob_interaction;

        if !has_any_definition {
            return Err(ScannerError::TemplateValidationError(
                "template must define at least one request, network, dns, tls, script, or feature block".to_string()
            ));
        }

        Ok(())
    }

    /// Lints the template to check for common issues or missing metadata.
    /// Returns a list of warning messages.
    pub fn lint(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.info.author.is_none() {
            warnings.push("Missing 'author' in template info".into());
        }

        if self.info.description.is_none() {
            warnings.push("Missing 'description' in template info".into());
        }

        if self.info.tags.is_empty() {
            warnings.push("Missing 'tags' in template info".into());
        }

        // ID format check (lowercase alphanumeric and hyphens)
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            warnings.push("Template 'id' should be lowercase, alphanumeric with hyphens".into());
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_valid_template_parsing() -> anyhow::Result<()> {
        let yaml = r#"
id: test-template
info:
  name: Test
  severity: Info
requests:
  - method: GET
    path: /
    matchers:
      - type: status
        part: status
        status:
          - 200
        "#;
        let mut file = NamedTempFile::new()?;
        writeln!(file, "{}", yaml)?;

        let template = VulnerabilityTemplate::load(file.path())?;
        assert_eq!(template.id, "test-template");
        assert_eq!(template.info.name, "Test");
        assert!(!template.requests.is_empty());
        Ok(())
    }

    #[test]
    fn test_invalid_template_parsing() -> anyhow::Result<()> {
        let yaml = r#"
id: test-template
info:
  name: Test
  severity: Info
invalid_key: true
        "#;

        let mut file = NamedTempFile::new()?;
        writeln!(file, "{}", yaml)?;

        let result = VulnerabilityTemplate::load(file.path());
        assert!(result.is_err(), "Serde should reject unknown fields");
        Ok(())
    }

    #[test]
    fn test_template_with_extractors() -> anyhow::Result<()> {
        let yaml = r#"
id: extractor-test
info:
  name: Extractor Demo
  severity: Medium
requests:
  - method: POST
    path: /login
    body: "username=admin&password=admin"
    extractors:
      - type: regex
        name: auth_token
        part: body
        regex: '"token":\s*"([^"]+)"'
        group: 1
    matchers:
      - type: status
        part: status
        status:
          - 200
  - method: GET
    path: /api/data
    headers:
      Authorization: "Bearer {{auth_token}}"
    matchers:
      - type: regex
        part: body
        regex:
          - "sensitive_data"
        "#;
        let mut file = NamedTempFile::new()?;
        writeln!(file, "{}", yaml)?;

        let template = VulnerabilityTemplate::load(file.path())?;
        assert_eq!(template.requests.len(), 2);
        assert!(!template.requests[0].extractors.is_empty());
        assert_eq!(template.requests[0].extractors[0].name, "auth_token");
        Ok(())
    }

    #[test]
    fn test_template_with_dns_and_tls() -> anyhow::Result<()> {
        let yaml = r#"
id: dns-tls-test
info:
  name: DNS and TLS Test
  severity: Info
dns:
  - domain: "{{Hostname}}"
    query_type: CNAME
    matchers:
      - type: regex
        part: body
        regex:
          - "cloudfront\\.net"
tls:
  - host: "{{Hostname}}"
    port: 443
    min_version: "TLSv1.2"
    matchers:
      - type: expired
        part: body
        "#;
        let mut file = NamedTempFile::new()?;
        writeln!(file, "{}", yaml)?;

        let template = VulnerabilityTemplate::load(file.path())?;
        assert!(!template.dns.is_empty());
        assert!(!template.tls.is_empty());
        assert_eq!(template.tls[0].min_version.as_deref(), Some("TLSv1.2"));
        Ok(())
    }
}
