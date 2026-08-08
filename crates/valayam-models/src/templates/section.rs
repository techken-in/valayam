use crate::error::ScannerError;

/// A single pluggable section within a `VulnerabilityTemplate`.
///
/// Every template section (HTTP request, DNS check, TLS audit, cloud scan, etc.)
/// implements this trait, enabling generic iteration, validation, and plugin dispatch
/// without matching on 50+ named fields.
pub trait TemplateSection: std::fmt::Debug + Send + Sync {
    /// Machine-readable section name used for plugin routing and error messages.
    /// Must be kebab-case (e.g. `"http-request"`, `"dns-audit"`).
    fn section_name(&self) -> &'static str;

    /// Human-readable description of what this section checks.
    fn section_description(&self) -> &str {
        ""
    }

    /// Validate section-internal consistency.
    /// Default implementation is a no-op; override to add field-level checks.
    fn validate(&self) -> Result<(), ScannerError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Macro: implement TemplateSection for a concrete type
// ---------------------------------------------------------------------------
// Usage: impl_template_section!(MyType, "my-section"[, "Optional description"]);

macro_rules! impl_template_section {
    ($ty:ty, $name:expr) => {
        impl TemplateSection for $ty {
            fn section_name(&self) -> &'static str {
                $name
            }
        }
    };
    ($ty:ty, $name:expr, $desc:expr) => {
        impl TemplateSection for $ty {
            fn section_name(&self) -> &'static str {
                $name
            }
            fn section_description(&self) -> &str {
                $desc
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Blanket impls for all section types
// ---------------------------------------------------------------------------
// NOTE: This list is kept in alphabetic order.  When adding a new section type,
// add its impl here.

impl_template_section!(super::auth_logic::AuthTemplate, "auth");
impl_template_section!(super::auth_logic::LogicTemplate, "logic");
impl_template_section!(super::auto_exploit::AutoExploitTemplate, "auto-exploit");
impl_template_section!(super::auto_redteam::AutoRedteamTemplate, "auto-redteam");
impl_template_section!(super::aws_escalate::AwsEscalateTemplate, "aws-escalate");
impl_template_section!(
    super::azure_gcp_escalate::AzureGcpEscalateTemplate,
    "azure-gcp-escalate"
);
impl_template_section!(super::browser_audit::BrowserAuditTemplate, "browser-audit");
impl_template_section!(super::cicd_audit::CicdAuditTemplate, "cicd-audit");
impl_template_section!(
    super::client_secret_audit::ClientSecretAuditTemplate,
    "client-secret-audit"
);
impl_template_section!(super::cloud_sec::CloudTemplate, "cloud");
impl_template_section!(
    super::container_audit::ContainerAuditTemplate,
    "container-audit"
);
impl_template_section!(super::cors_audit::CorsAuditTemplate, "cors-audit");
impl_template_section!(super::cred_monitor::CredMonitorTemplate, "cred-monitor");
impl_template_section!(super::csp_audit::CspAuditTemplate, "csp-audit");
impl_template_section!(super::ct_log_audit::CtLogAuditTemplate, "ct-log-audit");
impl_template_section!(super::deep_analysis::DeepAnalysisTemplate, "deep-analysis");
impl_template_section!(
    super::dependency_audit::DependencyAuditTemplate,
    "dependency-audit"
);
impl_template_section!(super::dns_audit::DnsRequestTemplate, "dns");
impl_template_section!(
    super::dom_redirect_audit::DomRedirectAuditTemplate,
    "dom-redirect-audit"
);
impl_template_section!(super::drift_detect::DriftDetectTemplate, "drift-detect");
impl_template_section!(super::easm::EasmTemplate, "easm");
impl_template_section!(super::fuzzer::FuzzTemplate, "fuzz");
impl_template_section!(super::graphql_audit::GraphqlAuditTemplate, "graphql-audit");
impl_template_section!(super::grpc_audit::GrpcAuditTemplate, "grpc-audit");
impl_template_section!(
    super::header_scorecard::HeaderScorecardTemplate,
    "header-scorecard"
);
impl_template_section!(super::http_scan::HttpRequestTemplate, "http-request");
impl_template_section!(super::iac_audit::IacAuditTemplate, "iac-audit");
impl_template_section!(super::idp_audit::IdpAuditTemplate, "idp-audit");
impl_template_section!(
    super::implant_deploy::ImplantDeployTemplate,
    "implant-deploy"
);
impl_template_section!(super::iot_audit::IotAuditTemplate, "iot-audit");
impl_template_section!(super::k8s_audit::K8sAuditTemplate, "k8s-audit");
impl_template_section!(super::mitre_mapping::MitreMappingTemplate, "mitre-mapping");
impl_template_section!(super::mobile_audit::MobileAuditTemplate, "mobile-audit");
impl_template_section!(super::network_scan::NetworkRequestTemplate, "network");
impl_template_section!(super::oauth_audit::OauthAuditTemplate, "oauth-audit");
impl_template_section!(
    super::pii_leak_audit::PiiLeakAuditTemplate,
    "pii-leak-audit"
);
impl_template_section!(super::port_scan::PortScanTemplate, "port-scan");
impl_template_section!(
    super::remediation_gen::RemediationGenTemplate,
    "remediation-gen"
);
impl_template_section!(
    super::reputation_audit::ReputationAuditTemplate,
    "reputation-audit"
);
impl_template_section!(super::sast_secrets::SastSecretsTemplate, "sast-secrets");
impl_template_section!(super::sast_taint::SastTaintTemplate, "sast-taint");
impl_template_section!(super::sbom_audit::SbomAuditTemplate, "sbom-audit");
impl_template_section!(super::scada_audit::ScadaAuditTemplate, "scada-audit");
impl_template_section!(super::schema_drift::SchemaDriftTemplate, "schema-drift");
impl_template_section!(super::scripting::ScriptTemplate, "script");
impl_template_section!(
    super::serverless_audit::ServerlessAuditTemplate,
    "serverless-audit"
);
impl_template_section!(
    super::subdomain_takeover::SubdomainTakeoverTemplate,
    "subdomain-takeover"
);
impl_template_section!(super::tls_audit::TlsAuditTemplate, "tls");
impl_template_section!(super::ui_proxy::UiProxyTemplate, "ui-proxy");
impl_template_section!(
    super::waf_bypass_verify::WafBypassVerifyTemplate,
    "waf-bypass-verify"
);
impl_template_section!(super::web3_audit::Web3AuditTemplate, "web3-audit");
