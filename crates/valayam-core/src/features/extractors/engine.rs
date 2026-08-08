use regex::Regex;
use std::collections::HashMap;
use valayam_models::templates::extractors::Extractor;

/// Extracts values from an HTTP response using the provided extractor rules.
///
/// Applies each extractor's regex against the appropriate response part
/// (body or headers) and returns a map of variable name → extracted value.
///
/// # Arguments
/// * `extractors` — The extractor rules from the template YAML.
/// * `body` — The raw response body bytes.
/// * `headers` — The response headers as a flat key-value map.
///
/// # Returns
/// A `HashMap<String, String>` of extracted variable names to their values.
/// Only successfully extracted values are included.
pub fn extract_from_response(
    extractors: &[Extractor],
    body: &[u8],
    headers: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut results = HashMap::new();
    let body_text = String::from_utf8_lossy(body);

    for extractor in extractors {
        if extractor.r#type == "css" {
            let Some(selector_str) = &extractor.css else {
                continue;
            };

            if let Ok(selector) = scraper::Selector::parse(selector_str) {
                let document = scraper::Html::parse_document(&body_text);
                if let Some(element) = document.select(&selector).next() {
                    let extracted = if let Some(attr) = &extractor.attribute {
                        element
                            .value()
                            .attr(attr)
                            .map(|v| v.to_string())
                            .unwrap_or_default()
                    } else {
                        element.text().collect::<Vec<_>>().join("")
                    };
                    results.insert(extractor.name.clone(), extracted);
                }
            }
            continue;
        }

        if extractor.r#type == "json" {
            let Some(pointer) = &extractor.json else {
                continue;
            };

            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
                if let Some(val) = v.pointer(pointer) {
                    let extracted = match val {
                        serde_json::Value::String(s) => s.to_string(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => val.to_string(),
                    };
                    results.insert(extractor.name.clone(), extracted);
                }
            }
            continue;
        }

        if extractor.r#type != "regex" {
            eprintln!(
                "[!] Unsupported extractor type: '{}'. Skipping.",
                extractor.r#type
            );
            continue;
        }

        let Some(pattern) = &extractor.regex else {
            continue;
        };

        let Ok(re) = Regex::new(pattern) else {
            eprintln!(
                "[!] Invalid extractor regex for '{}': '{}'. Skipping.",
                extractor.name, pattern
            );
            continue;
        };

        // Determine the text to search based on the part field
        let search_text = match extractor.part.as_str() {
            "header" => {
                // Concatenate all headers into a single string for regex matching
                headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            _ => body_text.to_string(), // Default: search body
        };

        // Apply regex and extract the specified capture group
        if let Some(caps) = re.captures(&search_text) {
            if let Some(matched) = caps.get(extractor.group) {
                results.insert(extractor.name.clone(), matched.as_str().to_string());
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_from_body() {
        let extractors = vec![Extractor {
            r#type: "regex".to_string(),
            name: "token".to_string(),
            part: "body".to_string(),
            regex: Some(r#""token":\s*"([^"]+)""#.to_string()),
            json: None,
            css: None,
            attribute: None,
            group: 1,
        }];

        let body = br#"{"token": "abc123xyz"}"#;
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("token").unwrap(), "abc123xyz");
    }

    #[test]
    fn test_extract_from_header() {
        let extractors = vec![Extractor {
            r#type: "regex".to_string(),
            name: "session".to_string(),
            part: "header".to_string(),
            regex: Some(r"session=([^;]+)".to_string()),
            json: None,
            css: None,
            attribute: None,
            group: 1,
        }];

        let body = b"";
        let mut headers = HashMap::new();
        headers.insert(
            "Set-Cookie".to_string(),
            "session=s3cr3t_value; Path=/".to_string(),
        );

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("session").unwrap(), "s3cr3t_value");
    }

    #[test]
    fn test_extract_no_match() {
        let extractors = vec![Extractor {
            r#type: "regex".to_string(),
            name: "missing".to_string(),
            part: "body".to_string(),
            regex: Some(r"not_here_(\d+)".to_string()),
            json: None,
            css: None,
            attribute: None,
            group: 1,
        }];

        let body = b"nothing matching";
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_multiple() {
        let extractors = vec![
            Extractor {
                r#type: "regex".to_string(),
                name: "csrf".to_string(),
                part: "body".to_string(),
                regex: Some(r#"csrf_token=([a-f0-9]+)"#.to_string()),
                json: None,
                css: None,
                attribute: None,
                group: 1,
            },
            Extractor {
                r#type: "regex".to_string(),
                name: "user_id".to_string(),
                part: "body".to_string(),
                regex: Some(r#""user_id":\s*(\d+)"#.to_string()),
                json: None,
                css: None,
                attribute: None,
                group: 1,
            },
        ];

        let body = br#"csrf_token=deadbeef and "user_id": 42"#;
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("csrf").unwrap(), "deadbeef");
        assert_eq!(result.get("user_id").unwrap(), "42");
    }

    #[test]
    fn test_extract_json_pointer() {
        let extractors = vec![
            Extractor {
                r#type: "json".to_string(),
                name: "token".to_string(),
                part: "body".to_string(),
                regex: None,
                json: Some("/auth/token".to_string()),
                css: None,
                attribute: None,
                group: 1,
            },
            Extractor {
                r#type: "json".to_string(),
                name: "expires".to_string(),
                part: "body".to_string(),
                regex: None,
                json: Some("/expires_in".to_string()),
                css: None,
                attribute: None,
                group: 1,
            },
        ];

        let body = br#"{"auth": {"token": "my-secret-jwt"}, "expires_in": 3600}"#;
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("token").unwrap(), "my-secret-jwt");
        assert_eq!(result.get("expires").unwrap(), "3600");
    }

    #[test]
    fn test_extract_css_selector() {
        let extractors = vec![
            Extractor {
                r#type: "css".to_string(),
                name: "csrf".to_string(),
                part: "body".to_string(),
                regex: None,
                json: None,
                css: Some("input[name=csrf_token]".to_string()),
                attribute: Some("value".to_string()),
                group: 1,
            },
            Extractor {
                r#type: "css".to_string(),
                name: "title".to_string(),
                part: "body".to_string(),
                regex: None,
                json: None,
                css: Some("title".to_string()),
                attribute: None,
                group: 1,
            },
        ];

        let body = br#"
            <html>
                <head><title>My Scanner Target</title></head>
                <body>
                    <form>
                        <input type="hidden" name="csrf_token" value="super-csrf-secret" />
                    </form>
                </body>
            </html>
        "#;
        let headers = HashMap::new();

        let result = extract_from_response(&extractors, body, &headers);
        assert_eq!(result.get("csrf").unwrap(), "super-csrf-secret");
        assert_eq!(result.get("title").unwrap(), "My Scanner Target");
    }
}
