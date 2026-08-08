use serde_json::Value;
use std::collections::HashSet;

/// Parses OpenAPI/Swagger JSON files and extracts all API routes and paths.
pub fn extract_openapi_endpoints(json_str: &str) -> HashSet<String> {
    let mut endpoints = HashSet::new();

    let Ok(v) = serde_json::from_str::<Value>(json_str) else {
        return endpoints;
    };

    if let Some(paths) = v.get("paths").and_then(|p| p.as_object()) {
        for path in paths.keys() {
            endpoints.insert(path.clone());
        }
    }

    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_openapi_endpoints() {
        let openapi_json = r#"{
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {}
                },
                "/users/{id}": {
                    "delete": {}
                }
            }
        }"#;

        let res = extract_openapi_endpoints(openapi_json);
        assert_eq!(res.len(), 2);
        assert!(res.contains("/users"));
        assert!(res.contains("/users/{id}"));
    }
}
