// - Benchmark `{{variable}}` context propagation under 1000+ concurrent templates.
// - Add telemetry spans for per-phase execution timing.
use super::schema::VulnerabilityTemplate;
use crate::features::http_scan;
use crate::network::http::StealthHttpClient;

use std::fs;
use std::path::Path;
use valayam_engine::rate_limiter::RateLimiter;
use valayam_engine::variables::build_initial_context;
use valayam_models::error::ScannerError;
use valayam_models::finding::FindingOwned;
use valayam_models::TemplateMetadata;

/// Orchestrates the execution of a single template against a target.
///
/// Executes feature slices in order: HTTP → Network → DNS → TLS → Scripts.
/// A shared `HashMap<String, String>` variable context flows through all phases.
/// Extractors from the HTTP phase populate the context for subsequent phases.
///
/// # Arguments
/// * `client` — The shared stealth HTTP client.
/// * `target_url` — The target URL to scan.
/// * `template` — The parsed template to execute.
/// * `rate_limiter` — Optional global rate limiter.
#[tracing::instrument(skip(client, template, rate_limiter), fields(target = %target_url, template = %template.id))]
pub async fn execute_template_inner(
    client: &StealthHttpClient,
    target_url: &str,
    template: &VulnerabilityTemplate,
    rate_limiter: Option<&RateLimiter>,
) -> Option<FindingOwned> {
    // Derive the bare hostname once for slices that need it
    let target_host = valayam_common::url::extract_host(target_url);

    // Build the shared variable context seeded with built-in variables
    let mut variables = build_initial_context(target_url, &target_host);

    // Moved to Wasm plugin

    // Phase 1: HTTP Requests (with extractors & helpers)
    if !template.requests.is_empty() {
        if let Some(rl) = rate_limiter {
            rl.acquire().await;
        }

        let results = http_scan::executor::execute(
            client,
            target_url,
            &template.requests,
            &template.id,
            &template.info as &dyn TemplateMetadata,
            &mut variables,
        )
        .await;
        if let Some(finding) = results.into_iter().next() {
            return Some(finding);
        }
    }

    // Phase 5: Script Execution & Fuzzing (Moved to Wasm plugin)

    // Phase 6: Cloud Probing
    // Moved to Wasm plugin

    // Phase 7: Stateful Logic & Authorization Testing (IDOR)
    // Moved to Wasm plugin

    // Phase 8: Deep Analysis & Evasion
    // Moved to Wasm plugin

    // Phase 9: IaC & SBOM Audit
    // Moved to Wasm plugin

    // Phase 10: gRPC & GraphQL Audit
    // Moved to Wasm plugin

    // Moved to Wasm plugin
    // Container audit logic moved to Wasm plugin
    // Moved to Wasm plugin

    // Phase 12: Zero-Trust & Identity Security
    // Moved to Wasm plugin

    // Phase 13: Multi-Cloud Post-Exploitation
    // Moved to Wasm plugin

    // Phase 21: Client-Side Security Auditing

    // Phase 14: Browser Exploitation
    // Browser audit templates deferred to WASM plugin
    let _ = template.browser_audit.is_empty();

    // Phase 15: Hardware & IoT Protocol Security (Moved to Wasm plugin)

    // Phase 20: Autonomous Red Teaming & Auto-Exploitation
    // Moved to Wasm plugin

    // Phase 21: Client-Side Security Auditing
    // Moved to Wasm plugin
    // Phase 21: dom_redirect_audit — deferred to WASM plugin
    // Phase 22: csp_audit — deferred to WASM plugin
    // Phase 23: header_scorecard — deferred to WASM plugin

    // Phase 24: Threat Intelligence & IP Reputation
    // Moved to Wasm plugin
    // Moved to Wasm plugin

    // Phase 25: Automated Reporting & Remediation Generation
    // Note: Remediation Generation is now handled in the outer wrapper if needed.
    // Phase 26: Container & Kubernetes Security Auditing
    // Moved to Wasm plugin

    // Phase 27: Source Code & Secrets Scanning (SAST)
    // Moved to Wasm plugin

    // Phase 28: Network & Port Security
    // Moved to Wasm plugin

    // Phase 30: CI/CD Pipeline & Supply Chain Security
    // Moved to Wasm plugin

    // Phase 31: Schema Drift / Shadow API detection
    if !template.schema_drift.is_empty() {
        if let Some(result) = valayam_schema_drift::executor::execute(
            target_url,
            client,
            &template.schema_drift,
            &template.id,
            &template.info as &dyn TemplateMetadata,
        )
        .await
        {
            return Some(result);
        }
    }

    None
}

#[deprecated(
    note = "Use ScanExecutor with PluginRegistry instead. This is maintained for valayam-platform backward compatibility."
)]
/// Documentation for this item.
pub async fn execute_template(
    client: &StealthHttpClient,
    target_url: &str,
    template: VulnerabilityTemplate,
    rate_limiter: Option<&RateLimiter>,
) -> Option<FindingOwned> {
    let result = execute_template_inner(client, target_url, &template, rate_limiter).await;

    if let Some(res) = result {
        // Mitre mapping and remediation gen moved to Wasm
        return Some(res);
    }

    None
}

/// Loader for vulnerability templates from disk or embedded sources
#[derive(Default, Clone)]
pub struct TemplateLoader;

impl TemplateLoader {
    /// Create a new template loader
    pub fn new() -> Self {
        Self
    }

    /// Recursively load all YAML templates from a directory path
    pub async fn load_directory(
        path: impl AsRef<Path>,
    ) -> Result<Vec<VulnerabilityTemplate>, ScannerError> {
        let path = path.as_ref().to_path_buf();

        // Spawn blocking for file I/O and parsing
        tokio::task::spawn_blocking(move || {
            let mut templates = Vec::new();
            Self::load_dir_recursive(&path, &mut templates)?;
            Ok(templates)
        })
        .await
        .map_err(|e| ScannerError::Other(Box::new(e)))?
    }

    /// Load a single template from a file path
    pub fn load_file(path: impl AsRef<Path>) -> Result<VulnerabilityTemplate, ScannerError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(ScannerError::TemplateReadError)?;

        let template: VulnerabilityTemplate = serde_yaml::from_str(&content)?;

        Ok(template)
    }

    fn load_dir_recursive(
        dir: &Path,
        templates: &mut Vec<VulnerabilityTemplate>,
    ) -> Result<(), ScannerError> {
        if !dir.is_dir() {
            return Ok(());
        }

        let entries = fs::read_dir(dir).map_err(ScannerError::TemplateReadError)?;
        for entry in entries {
            let entry = entry.map_err(ScannerError::TemplateReadError)?;
            let path = entry.path();

            if path.is_dir() {
                Self::load_dir_recursive(&path, templates)?;
            } else if let Some(ext) = path.extension() {
                if ext == "yaml" || ext == "yml" {
                    match Self::load_file(&path) {
                        Ok(t) => templates.push(t),
                        Err(e) => {
                            tracing::warn!(error = %e, path = %path.display(), "Failed to load template");
                            return Err(e);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
