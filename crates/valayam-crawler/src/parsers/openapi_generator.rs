use serde_json::Value;
use valayam_models::templates::http_scan::HttpRequestTemplate;
use valayam_models::templates::matcher::ResponseMatcher;
use valayam_models::templates::schema::{TemplateInfo, VulnerabilityTemplate};

/// Compiles an OpenAPI/Swagger spec string into a single native VulnerabilityTemplate.
pub fn generate_template_from_openapi(
    openapi_content: &str,
) -> Result<VulnerabilityTemplate, String> {
    let spec: Value = serde_json::from_str(openapi_content).map_err(|e| e.to_string())?;

    let title = spec
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .unwrap_or("Generated OpenAPI Scan");

    let description = spec
        .get("info")
        .and_then(|i| i.get("description"))
        .and_then(|d| d.as_str())
        .map(|s| s.to_string());

    let mut requests = Vec::new();

    if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
        for (path, path_val) in paths {
            if let Some(ops) = path_val.as_object() {
                for (method, _op_val) in ops {
                    let method_upper = method.to_uppercase();
                    if ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                        .contains(&method_upper.as_str())
                    {
                        let valayam_path = path.replace('{', "{{").replace('}', "}}");

                        let mut headers = std::collections::HashMap::new();
                        if ["POST", "PUT", "PATCH"].contains(&method_upper.as_str()) {
                            headers
                                .insert("Content-Type".to_string(), "application/json".to_string());
                        }

                        requests.push(HttpRequestTemplate {
                            method: method_upper,
                            path: valayam_path,
                            body: None,
                            headers: Some(headers),
                            matchers: vec![ResponseMatcher {
                                r#type: "status".to_string(),
                                part: "status".to_string(),
                                regex: vec![],
                                words: vec![],
                                status: Some(vec![200, 201, 204, 302, 401, 403]),
                                negative: false,
                                condition: "and".to_string(),
                            }],
                            matcher_condition: "and".to_string(),
                            extractors: vec![],
                            attack: None,
                            payloads: None,
                            inject_in: None,
                            follow_redirects: None,
                        });
                    }
                }
            }
        }
    }

    Ok(VulnerabilityTemplate {
        id: "generated-openapi-scan".to_string(),
        info: TemplateInfo {
            name: title.to_string(),
            severity: "Info".to_string(),
            description,
            compliance: Default::default(),
            author: None,
            tags: vec![],
        },
        requests,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_template_from_openapi() {
        let openapi_json = r#"{
            "openapi": "3.0.0",
            "info": {
                "title": "Test Service",
                "description": "API description"
            },
            "paths": {
                "/users/{id}": {
                    "get": {},
                    "delete": {}
                }
            }
        }"#;

        let template = generate_template_from_openapi(openapi_json).unwrap();
        assert_eq!(template.info.name, "Test Service");
        assert_eq!(template.info.description.unwrap(), "API description");
        assert_eq!(template.requests.len(), 2);

        let get_req = template
            .requests
            .iter()
            .find(|r| r.method == "GET")
            .unwrap();
        assert_eq!(get_req.path, "/users/{{id}}");
        assert_eq!(
            get_req.matchers[0].status.as_ref().unwrap(),
            &vec![200, 201, 204, 302, 401, 403]
        );
    }
}
