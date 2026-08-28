use std::collections::{HashMap, HashSet};
use semver::{Version, VersionReq};
use valayam_models::error::ScannerError;
use crate::vpa::PluginManifest;

/// Resolves plugin dependencies and returns an ordered list of plugin names
/// that guarantees dependencies are loaded before the plugins that depend on them.
pub fn resolve_dependencies(manifests: &[PluginManifest]) -> Result<Vec<String>, ScannerError> {
    let mut manifest_map: HashMap<String, &PluginManifest> = HashMap::new();
    for manifest in manifests {
        manifest_map.insert(manifest.name.clone(), manifest);
    }

    let mut graph: HashMap<String, Vec<String>> = HashMap::new();

    // Verify dependencies and build the directed graph
    for manifest in manifests {
        let mut deps = Vec::new();
        // Just validate the version string is semver, even if not strictly required for sorting
        let _plugin_version = match Version::parse(&manifest.version) {
            Ok(v) => v,
            Err(_) => return Err(ScannerError::PluginInitializationError(format!(
                "Invalid semver '{}' in plugin '{}'", manifest.version, manifest.name
            ))),
        };

        for dep in &manifest.dependencies {
            let dep_manifest = match manifest_map.get(&dep.name) {
                Some(m) => m,
                None => return Err(ScannerError::PluginInitializationError(format!(
                    "Missing dependency: '{}' requires '{}'", manifest.name, dep.name
                ))),
            };

            let req = match VersionReq::parse(&dep.version_req) {
                Ok(r) => r,
                Err(_) => return Err(ScannerError::PluginInitializationError(format!(
                    "Invalid version requirement '{}' for dependency '{}' in plugin '{}'",
                    dep.version_req, dep.name, manifest.name
                ))),
            };

            let dep_version = match Version::parse(&dep_manifest.version) {
                Ok(v) => v,
                Err(_) => return Err(ScannerError::PluginInitializationError(format!(
                    "Invalid semver '{}' in dependency plugin '{}'", dep_manifest.version, dep.name
                ))),
            };

            if !req.matches(&dep_version) {
                return Err(ScannerError::PluginInitializationError(format!(
                    "Dependency version mismatch: '{}' requires '{}' {}, but found version {}",
                    manifest.name, dep.name, dep.version_req, dep_version
                )));
            }

            deps.push(dep.name.clone());
        }
        graph.insert(manifest.name.clone(), deps);
    }

    // Topological Sort with Cycle Detection
    let mut sorted = Vec::new();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();

    for node in graph.keys() {
        if !visited.contains(node) {
            if has_cycle(node, &graph, &mut visited, &mut visiting, &mut sorted) {
                return Err(ScannerError::PluginInitializationError(
                    "Circular dependency detected in plugins".to_string(),
                ));
            }
        }
    }

    Ok(sorted)
}

fn has_cycle(
    node: &str,
    graph: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    visiting: &mut HashSet<String>,
    sorted: &mut Vec<String>,
) -> bool {
    if visiting.contains(node) {
        return true; // Cycle detected
    }
    if visited.contains(node) {
        return false;
    }

    visiting.insert(node.to_string());

    if let Some(neighbors) = graph.get(node) {
        for neighbor in neighbors {
            if has_cycle(neighbor, graph, visited, visiting, sorted) {
                return true;
            }
        }
    }

    visiting.remove(node);
    visited.insert(node.to_string());
    sorted.push(node.to_string());

    false
}
