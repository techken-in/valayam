use crate::features::schema_drift;
use crate::network::http::StealthHttpClient;
use async_trait::async_trait;
use std::sync::Arc;
use valayam_engine::traits::ScanContext;
use valayam_engine::traits::{PluginOutcome, ScanPlugin};
use valayam_models::templates::schema::{TemplateMetadata, VulnerabilityTemplate};

// ─── Native Plugins ─────────────────────────────────────────────────────────────

/// Documentation for this item.
pub struct HttpScanPlugin {
    client: Arc<StealthHttpClient>,
}

impl HttpScanPlugin {
    /// Documentation for this item.
    pub fn new(client: Arc<StealthHttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ScanPlugin for HttpScanPlugin {
    fn name(&self) -> &str {
        "http_scan"
    }

    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        template.has_section("http-request")
    }

    fn validate_config(
        &self,
        _template: &VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let mut vars = ctx.snapshot_variables().await;
        let template = ctx.template.clone();

        // Inject OOB variables if applicable
        if template.oob_interaction {
            let oob_id = valayam_oob::server::OobServer::generate_correlation_id();
            let oob_url = format!("{}.oob.valayam.local", oob_id);

            // Set for subsequent plugins (like OobPlugin)
            let mut ctx_vars = ctx.variables.write().await;
            ctx_vars.set_global("oob_correlation_id", &oob_id);
            ctx_vars.set_global("oob_url", &oob_url);
            drop(ctx_vars);

            // Set for the current HTTP executor
            vars.insert("oob_correlation_id".to_string(), oob_id);
            vars.insert("oob_url".to_string(), oob_url);
        }

        let results = crate::features::http_scan::executor::execute(
            &self.client,
            &ctx.target,
            &template.requests,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            &mut vars,
        )
        .await;

        if !results.is_empty() {
            if !template.deep_analysis.is_empty() {
                // Inject HTTP results so WASM plugins can access them
                let results_json = serde_json::to_string(&results).unwrap_or_default();
                ctx.variables
                    .write()
                    .await
                    .set_global("http_results", &results_json);

                for da_template in &template.deep_analysis {
                    let wasm_name = da_template.target.clone();
                    let path =
                        std::path::PathBuf::from(format!("plugins-wasm/bin/{}.wasm", wasm_name));
                    if path.exists() {
                        let plugin = valayam_engine::wasm_plugin::WasmPluginBridge::new(
                            wasm_name.clone(),
                            path,
                            valayam_engine::wasm_plugin::PluginConfig::default(),
                        );

                        tracing::info!(
                            "Handing off {} findings to WASM Plugin: {}",
                            results.len(),
                            wasm_name
                        );

                        let outcome = plugin.execute(ctx).await;
                        tracing::debug!(
                            "WASM Deep Analysis ({}) outcome: {:?}",
                            wasm_name,
                            outcome
                        );
                    } else {
                        tracing::warn!("WASM plugin {} not found at {:?}", wasm_name, path);
                    }
                }
            }

            for res in results {
                let _ = ctx.finding_tx.send(res).await;
            }
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
}

/// Documentation for this item.
pub struct SchemaDriftPlugin {
    client: Arc<StealthHttpClient>,
}

impl SchemaDriftPlugin {
    /// Documentation for this item.
    pub fn new(client: Arc<StealthHttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ScanPlugin for SchemaDriftPlugin {
    fn name(&self) -> &str {
        "schema_drift"
    }

    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        template.has_section("schema-drift")
    }

    fn validate_config(
        &self,
        _template: &VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        if let Some(res) = schema_drift::executor::execute(
            &ctx.target,
            &self.client,
            &ctx.template.schema_drift,
            &ctx.template.id,
            &ctx.template.info as &dyn TemplateMetadata,
        )
        .await
        {
            let _ = ctx.finding_tx.send(res).await;
            return PluginOutcome::Matched { count: 1 };
        }
        PluginOutcome::NoMatch
    }
}

/// Documentation for this item.
pub struct DnsAuditPlugin;
#[async_trait]
impl ScanPlugin for DnsAuditPlugin {
    fn name(&self) -> &str {
        "dns_audit"
    }
    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        template.has_section("dns")
    }

    fn validate_config(
        &self,
        _template: &VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let vars = ctx.snapshot_variables().await;
        let findings = valayam_core_net::features::dns_audit::executor::execute(
            &ctx.template.dns,
            &ctx.template.id,
            &ctx.template.info as &dyn TemplateMetadata,
            &vars,
        )
        .await;
        let count = findings.len();
        for f in findings {
            let _ = ctx.finding_tx.send(f).await;
        }
        if count > 0 {
            PluginOutcome::Matched { count }
        } else {
            PluginOutcome::NoMatch
        }
    }
}

/// Documentation for this item.
pub struct PortScanPlugin;
#[async_trait]
impl ScanPlugin for PortScanPlugin {
    fn name(&self) -> &str {
        "port_scan"
    }
    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        template.has_section("port-scan")
    }

    fn validate_config(
        &self,
        _template: &VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        if let Some(finding) = valayam_core_net::features::port_scan::executor::execute(
            &ctx.target,
            &ctx.template.port_scan,
            &ctx.template.id,
            &ctx.template.info as &dyn TemplateMetadata,
        )
        .await
        {
            let _ = ctx.finding_tx.send(finding).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
}

/// Documentation for this item.
pub struct ThreatIntelPlugin {
    /// Documentation for this item.
    pub matcher: Arc<crate::features::threat_intel::ioc_matcher::IocMatcher>,
}
#[async_trait]
impl ScanPlugin for ThreatIntelPlugin {
    fn name(&self) -> &str {
        "threat_intel"
    }
    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        template.id == "threat-intel" || template.has_section("threat-intel")
    }

    fn validate_config(
        &self,
        _template: &VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let host = valayam_common::url::extract_host(&ctx.target);

        let is_malicious =
            self.matcher.is_malicious_domain(&host) || self.matcher.is_malicious_ip(&host);

        if is_malicious {
            let finding = valayam_models::finding::FindingOwned {
                scan_id: ctx.scan_id,
                template_id: ctx.template.id.clone(),
                template_name: ctx.template.info.name.clone(),
                severity: valayam_models::finding::Severity::High,
                target: ctx.target.clone(),
                matched_at: host.clone(),
                description: Some("The target is communicating with or hosted on a known malicious infrastructure.".to_string()),
                solution: Some("Block traffic to this indicator and investigate internal systems communicating with it.".to_string()),
                extracted_data: Some(format!("Target host '{}' matched known threat intel indicators.", host)),
                metadata: std::collections::HashMap::new(),
            };
            let _ = ctx.finding_tx.send(finding).await;
            PluginOutcome::Matched { count: 1 }
        } else {
            PluginOutcome::NoMatch
        }
    }
}

/// Documentation for this item.
pub struct OobPlugin {
    /// Documentation for this item.
    pub server: Arc<valayam_oob::server::OobServer>,
}
#[async_trait]
impl ScanPlugin for OobPlugin {
    fn name(&self) -> &str {
        "oob"
    }
    fn is_applicable(&self, template: &VulnerabilityTemplate) -> bool {
        template.oob_interaction
    }

    fn validate_config(
        &self,
        _template: &VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }
    async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
        let _ = self.server.start().await; // Non-fatal if ports are occupied in testing
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let vars = ctx.snapshot_variables().await;
        let correlation_id = match vars.get("oob_correlation_id") {
            Some(id) => id.clone(),
            None => return PluginOutcome::NoMatch,
        };

        // Sleep to allow asynchronous network callbacks (DNS/HTTP) to arrive
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        if let Some(hits) = self.server.check_hits(&correlation_id).await {
            if !hits.is_empty() {
                let finding = valayam_models::finding::FindingOwned {
                    scan_id: ctx.scan_id,
                    template_id: ctx.template.id.clone(),
                    template_name: ctx.template.info.name.clone(),
                    severity: valayam_models::finding::Severity::Critical,
                    target: ctx.target.clone(),
                    matched_at: "Out-of-Band Callback".to_string(),
                    description: Some("The target triggered an out-of-band network interaction (DNS/HTTP) to our server, indicating a potential injection vulnerability (e.g., SSRF, RCE, or blind SQLi).".to_string()),
                    solution: Some("Validate and sanitize all inputs to prevent unintended network requests.".to_string()),
                    extracted_data: Some(format!("Received {} OOB interactions. First raw payload: {}", hits.len(), hits[0].raw_request)),
                    metadata: std::collections::HashMap::new(),
                };
                let _ = ctx.finding_tx.send(finding).await;
                return PluginOutcome::Matched { count: 1 };
            }
        }

        PluginOutcome::NoMatch
    }
}

/// Documentation for this item.
pub struct ShellsPlugin;
#[async_trait]
impl ScanPlugin for ShellsPlugin {
    fn name(&self) -> &str {
        "shells"
    }
    fn is_applicable(
        &self,
        template: &valayam_models::templates::schema::VulnerabilityTemplate,
    ) -> bool {
        template.has_section("shells") || template.id == "shells"
    }

    fn validate_config(
        &self,
        _template: &VulnerabilityTemplate,
    ) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), valayam_models::error::ScannerError> {
        Ok(())
    }
    async fn execute(&self, ctx: &ScanContext) -> PluginOutcome {
        let host = valayam_common::url::extract_host(&ctx.target);

        let ports = [4444, 31337];
        for port in ports {
            let addr = format!("{}:{}", host, port);
            if let Ok(Ok(_stream)) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                let finding = valayam_models::finding::FindingOwned {
                    scan_id: ctx.scan_id,
                    template_id: ctx.template.id.clone(),
                    template_name: ctx.template.info.name.clone(),
                    severity: valayam_models::finding::Severity::Critical,
                    target: ctx.target.clone(),
                    matched_at: addr.clone(),
                    description: Some(format!(
                        "Discovered an open port ({}) commonly used by reverse shells and malware.",
                        port
                    )),
                    solution: Some(
                        "Investigate the host for compromise immediately and block the port."
                            .to_string(),
                    ),
                    extracted_data: Some(format!(
                        "Successfully established TCP connection to {}",
                        addr
                    )),
                    metadata: std::collections::HashMap::new(),
                };
                let _ = ctx.finding_tx.send(finding).await;
                return PluginOutcome::Matched { count: 1 };
            }
        }
        PluginOutcome::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use valayam_models::templates::schema::VulnerabilityTemplate;

    fn empty_template() -> VulnerabilityTemplate {
        VulnerabilityTemplate {
            id: "test".to_string(),
            info: valayam_models::templates::schema::TemplateInfo {
                name: "Test".to_string(),
                severity: "Info".to_string(),
                author: None,
                description: None,
                tags: vec![],
                compliance: Default::default(),
            },
            ..VulnerabilityTemplate::empty()
        }
    }

    #[test]
    fn test_http_scan_plugin_new_and_name() {
        let client = Arc::new(
            crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap(),
        );
        let plugin = HttpScanPlugin::new(client);
        assert_eq!(plugin.name(), "http_scan");
    }

    #[test]
    fn test_http_scan_applicable_empty() {
        let client = Arc::new(
            crate::network::http::StealthHttpClient::new(false, false, None, false).unwrap(),
        );
        let plugin = HttpScanPlugin::new(client);
        assert!(!plugin.is_applicable(&empty_template()));
    }
}
