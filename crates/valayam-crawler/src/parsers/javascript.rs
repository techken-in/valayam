use regex::Regex;
use std::collections::HashSet;

/// Extracts API routes, paths, and URLs from a JavaScript bundle string.
pub fn extract_js_endpoints(js_content: &str) -> HashSet<String> {
    let mut endpoints = HashSet::new();

    let path_regex =
        Regex::new(r#"(?:"|')((?:/[a-zA-Z0-9_\-\.\?\,\'\/\+&\$#\=~\|\!]*){2,})(?:"|')"#)
            .expect("static regex: relative paths");

    let url_regex = Regex::new(r#"(https?|wss?|grpc)://[a-zA-Z0-9_\-\.:/\?&\$#\=~\|]+"#)
        .expect("static regex: absolute urls");

    for cap in path_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(1) {
            let val = matched.as_str();
            if !val.contains("//")
                && !val.ends_with(".js")
                && !val.ends_with(".css")
                && !val.ends_with(".png")
                && val.len() > 2
            {
                endpoints.insert(val.to_string());
            }
        }
    }

    for cap in url_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(0) {
            endpoints.insert(matched.as_str().to_string());
        }
    }

    endpoints
}

/// Extracts common query parameter keys and JSON payload keys from Javascript bundles.
pub fn extract_js_parameters(js_content: &str) -> HashSet<String> {
    let mut params = HashSet::new();

    let query_param_regex =
        Regex::new(r#"[?&]([a-zA-Z0-9_\-]+)="#).expect("static regex: query params");
    for cap in query_param_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(1) {
            params.insert(matched.as_str().to_string());
        }
    }

    let object_key_regex =
        Regex::new(r#"(?:"|')([a-zA-Z0-9_\-]+)(?:"|')\s*:"#).expect("static regex: object keys");
    for cap in object_key_regex.captures_iter(js_content) {
        if let Some(matched) = cap.get(1) {
            params.insert(matched.as_str().to_string());
        }
    }

    let ignore_words = [
        "default",
        "name",
        "type",
        "id",
        "true",
        "false",
        "null",
        "undefined",
        "const",
        "let",
        "var",
        "function",
        "return",
        "class",
        "import",
        "export",
    ];
    params.retain(|p| !ignore_words.contains(&p.as_str()) && !p.is_empty());

    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_js_endpoints() {
        let js = r#"
            const api = "/api/v1/users";
            fetch('/api/v2/posts?limit=10');
            const ws = "wss://localhost:8080/stream";
            let path = "/dashboard/settings";
        "#;
        let res = extract_js_endpoints(js);
        assert!(res.contains("/api/v1/users"));
        assert!(res.contains("/api/v2/posts?limit=10"));
        assert!(res.contains("/dashboard/settings"));
        assert!(res.contains("wss://localhost:8080/stream"));
    }

    #[test]
    fn test_extract_js_parameters() {
        let js = r#"
            const params = {
                "username": "admin",
                'password': "123",
                "csrf_token": "token"
            };
            fetch('/api/search?q=rust&limit=5');
        "#;
        let res = extract_js_parameters(js);
        assert!(res.contains("username"));
        assert!(res.contains("password"));
        assert!(res.contains("csrf_token"));
        assert!(res.contains("q"));
        assert!(res.contains("limit"));
        assert!(!res.contains("default"));
    }
}
