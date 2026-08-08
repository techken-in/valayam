use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use md5;
use sha2::{Digest, Sha256};

/// Dispatches a helper function call to the appropriate implementation.
/// Returns `None` if the function name is not recognized.
pub fn call_helper(func_name: &str, arg: &str) -> Option<String> {
    match func_name {
        "base64" => Some(helper_base64(arg)),
        "base64_decode" => Some(helper_base64_decode(arg)),
        "url_encode" => Some(helper_url_encode(arg)),
        "url_decode" => Some(helper_url_decode(arg)),
        "md5" => Some(helper_md5(arg)),
        "sha256" => Some(helper_sha256(arg)),
        "hex_encode" => Some(helper_hex_encode(arg)),
        "to_lower" => Some(helper_to_lower(arg)),
        "to_upper" => Some(helper_to_upper(arg)),
        _ => None,
    }
}

/// Base64 encode a string.
fn helper_base64(input: &str) -> String {
    BASE64_STANDARD.encode(input.as_bytes())
}

/// Base64 decode a string. Returns the original input on decode failure.
fn helper_base64_decode(input: &str) -> String {
    BASE64_STANDARD
        .decode(input.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| input.to_string())
}

/// Percent-encode a string for use in URLs.
fn helper_url_encode(input: &str) -> String {
    url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

/// Percent-decode a URL-encoded string.
fn helper_url_decode(input: &str) -> String {
    // Decode percent-encoded bytes back to UTF-8
    let decoded_bytes: Vec<u8> = input.as_bytes().to_vec();
    // Use form_urlencoded to parse a single key which effectively decodes it
    url::form_urlencoded::parse(&decoded_bytes)
        .map(|(k, v)| {
            if v.is_empty() {
                k.to_string()
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Compute the MD5 hex digest of a string.
fn helper_md5(input: &str) -> String {
    let digest = md5::compute(input.as_bytes());
    format!("{:x}", digest)
}

/// Compute the SHA-256 hex digest of a string.
fn helper_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

/// Hex-encode a string's bytes.
fn helper_hex_encode(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Convert a string to lowercase.
fn helper_to_lower(input: &str) -> String {
    input.to_lowercase()
}

/// Convert a string to uppercase.
fn helper_to_upper(input: &str) -> String {
    input.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let encoded = helper_base64("admin:password");
        assert_eq!(encoded, "YWRtaW46cGFzc3dvcmQ=");
        let decoded = helper_base64_decode(&encoded);
        assert_eq!(decoded, "admin:password");
    }

    #[test]
    fn test_url_encode_decode() {
        let encoded = helper_url_encode("<script>alert(1)</script>");
        assert!(encoded.contains("%3C"));
        let decoded = helper_url_decode(&encoded);
        assert_eq!(decoded, "<script>alert(1)</script>");
    }

    #[test]
    fn test_md5() {
        assert_eq!(helper_md5("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_sha256() {
        assert_eq!(
            helper_sha256("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(helper_hex_encode("ABC"), "414243");
    }

    #[test]
    fn test_case_conversion() {
        assert_eq!(helper_to_lower("HeLLo"), "hello");
        assert_eq!(helper_to_upper("hello"), "HELLO");
    }

    #[test]
    fn test_unknown_function() {
        assert!(call_helper("nonexistent", "arg").is_none());
    }
}
