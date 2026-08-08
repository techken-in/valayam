use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::{debug, info, warn};
use valayam_crawler::Crawler;
use valayam_error::ScannerError;
use valayam_models::finding::FindingOwned;
use valayam_models::templates::schema_drift::SchemaDriftTemplate;
use valayam_models::TemplateMetadata;
use valayam_network::network::http::StealthHttpClient;

// ---------------------------------------------------------------------------
// Schema version history — persisted between scans so we can detect when
// endpoints have been added to or removed from the specification.
// ---------------------------------------------------------------------------

/// Metadata about a single API endpoint extracted from an OpenAPI spec.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
struct EndpointDescriptor {
    path: String,
    method: String,
}

/// State persisted for a single schema drift check.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct SchemaDriftState {
    /// Hex hash of the full OpenAPI document (used to detect spec changes).
    schema_hash: String,
    /// Set of endpoints extracted from the spec at last scan.
    documented_endpoints: Vec<EndpointDescriptor>,
    /// ISO-8601 timestamp of the last scan.
    last_scan: DateTime<Utc>,
    /// Number of times this baseline has been checked.
    scan_count: u64,
}

const SCHEMA_STATE_DIR: &str = ".valayam-state";

fn schema_state_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

fn schema_state_path(template_id: &str) -> PathBuf {
    PathBuf::from(SCHEMA_STATE_DIR).join(format!("schema_drift_{}.json", template_id))
}

fn load_schema_state(template_id: &str) -> Result<Option<SchemaDriftState>, ScannerError> {
    let path = schema_state_path(template_id);
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path).map_err(ScannerError::TemplateReadError)?;
    match serde_json::from_str(&contents) {
        Ok(state) => Ok(Some(state)),
        Err(e) => {
            warn!(
                template_id = %template_id,
                error = %e,
                "Schema drift state file corrupted; starting fresh"
            );
            Ok(None)
        }
    }
}

fn save_schema_state(template_id: &str, state: &SchemaDriftState) -> Result<(), ScannerError> {
    let _lock = schema_state_lock()
        .lock()
        .map_err(|e| ScannerError::ConfigurationError(format!("Schema state lock error: {}", e)))?;
    let path = schema_state_path(template_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ScannerError::ConfigurationError(format!(
                "Failed to create schema state directory: {}",
                e
            ))
        })?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| {
        ScannerError::ParseError(format!("Failed to serialize schema state: {}", e))
    })?;
    // Atomic write: temp file, then rename
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &json).map_err(|e| {
        ScannerError::ConfigurationError(format!("Failed to write schema state: {}", e))
    })?;
    std::fs::rename(&tmp_path, &path).map_err(|e| {
        ScannerError::ConfigurationError(format!("Failed to commit schema state: {}", e))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenAPI spec parsing helpers
// ---------------------------------------------------------------------------

/// Parse an OpenAPI spec string (JSON or YAML) and return a computed hash and
/// the set of documented endpoint descriptors.
fn parse_openapi_spec(spec_str: &str) -> Result<(String, Vec<EndpointDescriptor>), String> {
    // Try JSON first, then YAML
    let spec: serde_json::Value = serde_json::from_str(spec_str).or_else(|_| {
        serde_yaml::from_str::<serde_json::Value>(spec_str)
            .map_err(|e| format!("Failed to parse OpenAPI spec as JSON or YAML: {}", e))
    })?;

    // Compute a hash of the normalized JSON representation (sorted keys)
    let normalized = serde_json::to_string(&spec)
        .map_err(|e| format!("Failed to normalize OpenAPI spec: {}", e))?;
    let schema_hash = format!("{:x}", md5::compute(normalized.as_bytes()));

    // Validate the parsed result is actually a JSON object with a "paths" key.
    if !spec.is_object() {
        return Err("Parsed OpenAPI spec is not a valid JSON object. Ensure the document contains a 'paths' section.".to_string());
    }

    let mut endpoints = Vec::new();

    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
        for (path, path_item) in paths {
            if let Some(ops) = path_item.as_object() {
                for (method, _) in ops {
                    let method_upper = method.to_uppercase();
                    if ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                        .contains(&method_upper.as_str())
                    {
                        let normalised_path = path.replace('{', "{{").replace('}', "}}");
                        endpoints.push(EndpointDescriptor {
                            path: normalised_path,
                            method: method_upper,
                        });
                    }
                }
            }
        }
    }

    // Sort endpoints for deterministic comparison
    endpoints.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    Ok((schema_hash, endpoints))
}

/// Extract the path component from a raw URL, discarding query strings,
/// scheme, and host.
fn extract_path(url: &str) -> String {
    let without_query = url.split('?').next().unwrap_or(url);
    if let Some(scheme_end) = without_query.find("://") {
        let after_scheme = &without_query[scheme_end + 3..];
        if let Some(path_start) = after_scheme.find('/') {
            after_scheme[path_start..].to_string()
        } else {
            "/".to_string()
        }
    } else {
        without_query.to_string()
    }
}

/// Check whether a discovered URL path matches a documented endpoint path,
/// accounting for variable placeholders (e.g. `/users/{{id}}` matches `/users/42`).
fn path_matches_documented(discovered_path: &str, doc_path: &str) -> bool {
    let discovered_segments: Vec<&str> =
        discovered_path.trim_start_matches('/').split('/').collect();
    let doc_segments: Vec<&str> = doc_path.trim_start_matches('/').split('/').collect();

    if discovered_segments.len() != doc_segments.len() {
        return false;
    }

    for (d_seg, doc_seg) in discovered_segments.iter().zip(doc_segments.iter()) {
        if doc_seg.starts_with("{{") && doc_seg.ends_with("}}") {
            continue;
        }
        if d_seg != doc_seg {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Diff computation
// ---------------------------------------------------------------------------

/// Result of comparing documented vs. discovered endpoints.
#[derive(Debug, Default)]
struct SchemaDiff {
    shadow_apis: Vec<String>,
    missing_endpoints: Vec<EndpointDescriptor>,
}

fn compute_schema_diff(
    documented: &[EndpointDescriptor],
    discovered: &HashSet<String>,
) -> SchemaDiff {
    let mut diff = SchemaDiff::default();

    // Detect shadow APIs: discovered URLs that do not match any documented path
    for url in discovered {
        let path = extract_path(url);
        let is_documented = documented
            .iter()
            .any(|ep| path_matches_documented(&path, &ep.path));
        if !is_documented {
            diff.shadow_apis.push(path);
        }
    }

    // Detect missing endpoints: documented paths that were not found during crawl
    let discovered_set: HashSet<String> = discovered.iter().map(|u| extract_path(u)).collect();
    for ep in documented {
        let discovered_match = discovered_set
            .iter()
            .any(|d| path_matches_documented(d, &ep.path));
        if !discovered_match {
            diff.missing_endpoints.push(ep.clone());
        }
    }

    diff
}

/// Compare two sets of documented endpoints and report what has changed in the spec itself.
fn detect_schema_spec_changes(
    old_endpoints: &[EndpointDescriptor],
    new_endpoints: &[EndpointDescriptor],
) -> Vec<String> {
    let old_set: HashSet<&EndpointDescriptor> = old_endpoints.iter().collect();
    let new_set: HashSet<&EndpointDescriptor> = new_endpoints.iter().collect();

    let mut changes = Vec::new();

    let added: Vec<&&EndpointDescriptor> = new_set.difference(&old_set).collect();
    let removed: Vec<&&EndpointDescriptor> = old_set.difference(&new_set).collect();

    if !added.is_empty() {
        let detail: Vec<String> = added
            .iter()
            .map(|ep| format!("{} {}", ep.method, ep.path))
            .collect();
        changes.push(format!("Endpoints added to spec: {}", detail.join(", ")));
    }
    if !removed.is_empty() {
        let detail: Vec<String> = removed
            .iter()
            .map(|ep| format!("{} {}", ep.method, ep.path))
            .collect();
        changes.push(format!(
            "Endpoints removed from spec: {}",
            detail.join(", ")
        ));
    }

    changes
}

// ---------------------------------------------------------------------------
// Public executor
// ---------------------------------------------------------------------------

/// Execute schema drift detection against a target.
///
/// For each template:
/// 1. Parse the OpenAPI spec (JSON or YAML) to extract documented endpoints.
/// 2. Crawl the target to discover actual endpoints.
/// 3. Compare documented vs. discovered to find shadow APIs and missing endpoints.
/// 4. Track schema version history and report spec changes between scans.
/// 5. Return a `ScanResult` if any drift is found.
pub async fn execute(
    target_host: &str,
    http_client: &StealthHttpClient,
    templates: &[SchemaDriftTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host = template.target.replace("{{Hostname}}", target_host);
        let crawl_depth = template.crawl_depth;
        let spec_content = &template.openapi_spec;

        debug!(
            target = %host,
            crawl_depth = crawl_depth as usize,
            "Executing schema drift detection"
        );

        // -----------------------------------------------------------------------
        // Step 1: Parse the OpenAPI spec
        // -----------------------------------------------------------------------
        let (current_schema_hash, documented_endpoints) = match parse_openapi_spec(spec_content) {
            Ok(result) => result,
            Err(e) => {
                warn!(target = %host, error = %e, "Failed to parse OpenAPI spec");
                continue;
            }
        };

        if documented_endpoints.is_empty() {
            debug!(target = %host, "OpenAPI spec contains no parseable endpoints");
        }

        // -----------------------------------------------------------------------
        // Step 2: Crawl the target to discover actual endpoints
        // -----------------------------------------------------------------------
        let crawler = match Crawler::new(
            Arc::new(http_client.clone()),
            &host,
            crawl_depth as usize,
            None,
            None,
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    target = %host,
                    error = %e,
                    "Failed to initialise crawler for schema drift"
                );
                continue;
            }
        };

        let discovered_urls = crawler.run().await;

        if discovered_urls.is_empty() {
            debug!(target = %host, "Crawler returned no discovered URLs");
        }

        // -----------------------------------------------------------------------
        // Step 3: Compute diff between documented and discovered
        // -----------------------------------------------------------------------
        let diff = compute_schema_diff(&documented_endpoints, &discovered_urls);

        // -----------------------------------------------------------------------
        // Step 4: Track schema version history
        // -----------------------------------------------------------------------
        let mut schema_changes = Vec::new();
        let mut scan_count: u64 = 0;

        if let Ok(Some(prev_state)) = load_schema_state(template_id) {
            scan_count = prev_state.scan_count;

            // Detect if the spec itself has changed since last scan
            if prev_state.schema_hash != current_schema_hash {
                info!(
                    template_id = %template_id,
                    "OpenAPI spec has changed since last scan"
                );
                let spec_changes = detect_schema_spec_changes(
                    &prev_state.documented_endpoints,
                    &documented_endpoints,
                );
                schema_changes.extend(spec_changes);
            }
        }

        // Persist current state for next scan
        let new_state = SchemaDriftState {
            schema_hash: current_schema_hash,
            documented_endpoints: documented_endpoints.clone(),
            last_scan: Utc::now(),
            scan_count: scan_count + 1,
        };

        if let Err(e) = save_schema_state(template_id, &new_state) {
            warn!(
                template_id = %template_id,
                error = %e,
                "Failed to persist schema drift state"
            );
        }

        // -----------------------------------------------------------------------
        // Step 5: Build payload and return result if drift found
        // -----------------------------------------------------------------------
        let mut findings: Vec<String> = Vec::new();

        if !diff.shadow_apis.is_empty() {
            findings.push(format!(
                "Shadow APIs ({}) — discovered but undocumented: {:?}",
                diff.shadow_apis.len(),
                diff.shadow_apis
            ));
        }

        if !diff.missing_endpoints.is_empty() {
            let missing_detail: Vec<String> = diff
                .missing_endpoints
                .iter()
                .map(|ep| format!("{} {}", ep.method, ep.path))
                .collect();
            findings.push(format!(
                "Missing endpoints ({}) — documented but not reachable: {:?}",
                diff.missing_endpoints.len(),
                missing_detail
            ));
        }

        findings.extend(schema_changes);

        if !findings.is_empty() {
            let total = findings.len();

            info!(
                target = %host,
                template_id = %template_id,
                findings = total,
                scan_count = scan_count + 1,
                "Schema drift detected"
            );

            return Some({
                let tag2 = if diff.shadow_apis.is_empty() {
                    "spec-change"
                } else {
                    "shadow-api"
                };
                let mut meta = HashMap::new();
                meta.insert("template_id".to_string(), template_id.to_string());
                meta.insert(
                    "template_name".to_string(),
                    template_meta.template_name().to_string(),
                );
                meta.insert(
                    "template_severity".to_string(),
                    template_meta.template_severity().to_string(),
                );
                meta.insert("tags".to_string(), format!("schema-drift,{}", tag2));
                FindingOwned::from_template(
                    host.clone(),
                    format!(
                        "Schema drift detected (scan #{}) — {} finding(s):\n{}",
                        scan_count + 1,
                        total,
                        findings.join("\n"),
                    ),
                    meta,
                )
            });
        } else {
            debug!(
                target = %host,
                template_id = %template_id,
                scan_count = scan_count + 1,
                "No schema drift detected"
            );
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // parse_openapi_spec tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_openapi_json() {
        let spec = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/users": { "get": {}, "post": {} },
                "/users/{id}": { "get": {}, "delete": {} }
            }
        }"#;

        let (hash, endpoints) = parse_openapi_spec(spec).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(endpoints.len(), 4);

        let methods: Vec<&str> = endpoints.iter().map(|e| e.method.as_str()).collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"POST"));
        assert!(methods.contains(&"DELETE"));
    }

    #[test]
    fn test_parse_openapi_yaml() {
        let spec = r#"
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
paths:
  /health:
    get:
      summary: Health check
        "#;

        let (hash, endpoints) = parse_openapi_spec(spec).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/health");
        assert_eq!(endpoints[0].method, "GET");
    }

    #[test]
    fn test_parse_openapi_invalid() {
        let result = parse_openapi_spec("not-json-or-yaml-at-all{{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_openapi_empty_paths() {
        let spec = r#"{"openapi":"3.0.0","paths":{}}"#;
        let (hash, endpoints) = parse_openapi_spec(spec).unwrap();
        assert!(!hash.is_empty());
        assert!(endpoints.is_empty());
    }

    // -----------------------------------------------------------------------
    // path_matches_documented tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_path_matches_exact() {
        assert!(path_matches_documented("/api/v1/users", "/api/v1/users"));
    }

    #[test]
    fn test_path_matches_wildcard() {
        assert!(path_matches_documented("/users/42", "/users/{{id}}"));
    }

    #[test]
    fn test_path_does_not_match_different_segments() {
        assert!(!path_matches_documented(
            "/users/42/profile",
            "/users/{{id}}"
        ));
    }

    #[test]
    fn test_path_does_not_match_different_base() {
        assert!(!path_matches_documented("/api/v2/users", "/api/v1/users"));
    }

    #[test]
    fn test_path_matches_multiple_freecards() {
        assert!(path_matches_documented(
            "/org/abc/project/def/resource",
            "/org/{{org_id}}/project/{{proj_id}}/resource"
        ));
    }

    // -----------------------------------------------------------------------
    // compute_schema_diff tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_drift_when_all_discovered_are_documented() {
        let documented = vec![
            EndpointDescriptor {
                path: "/api/users".to_string(),
                method: "GET".to_string(),
            },
            EndpointDescriptor {
                path: "/api/health".to_string(),
                method: "GET".to_string(),
            },
        ];
        let discovered: HashSet<String> = vec![
            "http://example.com/api/users".to_string(),
            "http://example.com/api/health".to_string(),
        ]
        .into_iter()
        .collect();

        let diff = compute_schema_diff(&documented, &discovered);
        assert!(diff.shadow_apis.is_empty());
        assert!(diff.missing_endpoints.is_empty());
    }

    #[test]
    fn test_shadow_api_detected() {
        let documented = vec![EndpointDescriptor {
            path: "/api/users".to_string(),
            method: "GET".to_string(),
        }];
        let discovered: HashSet<String> = vec![
            "http://example.com/api/users".to_string(),
            "http://example.com/api/admin".to_string(), // shadow
        ]
        .into_iter()
        .collect();

        let sp = compute_schema_diff(&documented, &discovered);
        assert_eq!(sp.shadow_apis.len(), 1);
        assert!(sp.shadow_apis[0].contains("admin"));
    }

    #[test]
    fn test_taining_endpoint_detected() {
        let documented = vec![
            EndpointDescriptor {
                path: "/api/users".to_string(),
                method: "GET".to_string(),
            },
            EndpointDescriptor {
                path: "/api/secret".to_string(),
                method: "GET".to_string(),
            }, // missing
        ];
        let discovered: HashSet<String> = vec!["http://example.com/api/users".to_string()]
            .into_iter()
            .collect();

        let diff = compute_schema_diff(&documented, &discovered);
        assert_eq!(diff.missing_endpoints.len(), 1);
        assert!(diff.missing_endpoints[0].path.contains("secret"));
    }

    #[test]
    fn test_wildcard_path_matches_in_diff() {
        let documented = vec![EndpointDescriptor {
            path: "/users/{{id}}".to_string(),
            method: "GET".to_string(),
        }];
        let discovered: HashSet<String> = vec![
            "http://example.com/users/42".to_string(),
            "http://example.com/users/abc".to_string(),
        ]
        .into_iter()
        .collect();

        let diff = compute_schema_diff(&documented, &discovered);
        assert!(
            diff.shadow_apis.is_empty(),
            "Wildcard should match multiple discovered paths"
        );
    }

    // -----------------------------------------------------------------------
    // detect_schema_spec_changes tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_spec_added_endpoints() {
        let old = vec![EndpointDescriptor {
            path: "/api/v1".to_string(),
            method: "GET".to_string(),
        }];
        let new = vec![
            EndpointDescriptor {
                path: "/api/v1".to_string(),
                method: "GET".to_string(),
            },
            EndpointDescriptor {
                path: "/api/v2".to_string(),
                method: "POST".to_string(),
            },
        ];

        let changes = detect_schema_spec_changes(&old, &new);
        assert!(
            changes.iter().any(|c| c.contains("added")),
            "Added endpoints should be reported"
        );
    }

    #[test]
    fn test_spec_removed_endpoints() {
        let old = vec![
            EndpointDescriptor {
                path: "/api/v1".to_string(),
                method: "GET".to_string(),
            },
            EndpointDescriptor {
                path: "/api/v2".to_string(),
                method: "POST".to_string(),
            },
        ];
        let new = vec![EndpointDescriptor {
            path: "/api/v1".to_string(),
            method: "GET".to_string(),
        }];

        let changes = detect_schema_spec_changes(&old, &new);
        assert!(
            changes.iter().any(|c| c.contains("removed")),
            "Removed endpoints should be reported"
        );
    }

    #[test]
    fn test_spec_no_changes() {
        let endpoints = vec![EndpointDescriptor {
            path: "/api/v1".to_string(),
            method: "GET".to_string(),
        }];
        let changes = detect_schema_spec_changes(&endpoints, &endpoints);
        assert!(changes.is_empty());
    }

    // -----------------------------------------------------------------------
    // extract_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_path_no_query() {
        assert_eq!(extract_path("/api/users"), "/api/users");
    }

    #[test]
    fn test_extract_path_with_query() {
        assert_eq!(extract_path("/api/users?page=1"), "/api/users");
    }

    #[test]
    fn test_extract_path_full_url() {
        assert_eq!(
            extract_path("http://example.com/api/users?token=abc"),
            "/api/users"
        );
    }
}
