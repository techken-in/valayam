use regex::Regex;
use std::collections::HashSet;

/// Extracts printable ASCII strings from WebAssembly binary bytes and
/// filters for potential API paths and URLs.
pub fn extract_wasm_endpoints(wasm_bytes: &[u8]) -> HashSet<String> {
    let mut endpoints = HashSet::new();

    let mut current_str = Vec::new();
    let mut strings = Vec::new();

    for &byte in wasm_bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            current_str.push(byte);
        } else {
            if current_str.len() >= 4 {
                if let Ok(s) = String::from_utf8(current_str.clone()) {
                    strings.push(s);
                }
            }
            current_str.clear();
        }
    }
    if current_str.len() >= 4 {
        if let Ok(s) = String::from_utf8(current_str) {
            strings.push(s);
        }
    }

    let path_regex =
        Regex::new(r#"^/[a-zA-Z0-9_\-\./\?&\$#\=~\|]+$"#).expect("static regex: wasm paths");
    let url_regex = Regex::new(r#"^(https?|wss?|grpc)://[a-zA-Z0-9_\-\./\?&\$#\=~\|]+$"#)
        .expect("static regex: wasm urls");

    for s in strings {
        let trimmed = s.trim();
        if path_regex.is_match(trimmed) {
            if trimmed.len() > 2 && !trimmed.contains("//") {
                endpoints.insert(trimmed.to_string());
            }
        } else if url_regex.is_match(trimmed) {
            endpoints.insert(trimmed.to_string());
        }
    }

    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_wasm_endpoints() {
        let mut wasm_mock = vec![0x00, 0x61, 0x73, 0x6d];
        wasm_mock.extend_from_slice(b"\x00/api/v1/compiled/endpoint\x00");
        wasm_mock.extend_from_slice(b"\x00https://wasm-api-server.internal/graphql\x00");

        let res = extract_wasm_endpoints(&wasm_mock);
        assert!(res.contains("/api/v1/compiled/endpoint"));
        assert!(res.contains("https://wasm-api-server.internal/graphql"));
    }
}
