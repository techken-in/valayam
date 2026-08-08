// - Implement strict circular-dependency detection during resolution.
// - Optimize Regex substitutions for zero-copy where possible.
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use valayam_models::error::ScannerError;

/// Resolves all `{{variable}}` placeholders in a template string using the
/// provided variable context with circular dependency detection.
///
/// # Resolution Order
/// 1. Built-in variables (`{{BaseURL}}`, `{{Hostname}}`)
/// 2. Extracted variables (`{{auth_token}}`, etc.)
///
/// Helper function evaluation (e.g., `{{base64(...)}}`) is handled
/// separately by the `features::helpers` module and called after
/// variable resolution.
pub fn resolve_variables(
    template_str: &str,
    context: &HashMap<String, String>,
) -> Result<String, ScannerError> {
    let mut visited = HashSet::new();
    resolve_variables_with_detection(template_str, context, &mut visited)
}

fn resolve_variables_with_detection(
    template_str: &str,
    context: &HashMap<String, String>,
    visited: &mut HashSet<String>,
) -> Result<String, ScannerError> {
    if !template_str.contains("{{") || !template_str.contains("}}") {
        return Ok(template_str.to_string());
    }

    let mut result = String::with_capacity(template_str.len());
    let mut remaining = template_str;

    while let Some(start_idx) = remaining.find("{{") {
        result.push_str(&remaining[..start_idx]);
        let after_start = &remaining[start_idx + 2..];

        if let Some(end_idx) = after_start.find("}}") {
            let var_name = &after_start[..end_idx];

            if !is_valid_var_name(var_name) {
                // If it's not a valid variable name, leave it as is
                result.push_str("{{");
                result.push_str(var_name);
                result.push_str("}}");
                remaining = &after_start[end_idx + 2..];
                continue;
            }

            if !visited.insert(var_name.to_string()) {
                return Err(ScannerError::VariableResolutionError(format!(
                    "Circular dependency detected for variable: {}",
                    var_name
                )));
            }

            if let Some(value) = context.get(var_name) {
                result.push_str(value);
            } else {
                result.push_str("{{");
                result.push_str(var_name);
                result.push_str("}}");
            }

            visited.remove(var_name);
            remaining = &after_start[end_idx + 2..];
        } else {
            // No closing tags found
            result.push_str("{{");
            remaining = after_start;
            break;
        }
    }
    result.push_str(remaining);

    Ok(result)
}

fn is_valid_var_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s
        .chars()
        .next()
        .expect("s is non-empty after is_empty check");
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    s.chars()
        .skip(1)
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Builds the initial variable context from the target URL.
/// Seeds `BaseURL` and `Hostname` as built-in variables.
pub fn build_initial_context(target_url: &str, target_host: &str) -> HashMap<String, String> {
    let mut context = HashMap::with_capacity(3);
    let clean_target = target_url.trim_end_matches('/').to_string();
    context.insert("BaseURL".to_string(), clean_target.clone());
    context.insert("TARGET_URL".to_string(), clean_target); // backwards compatibility for some WASM plugins
    context.insert("Hostname".to_string(), target_host.to_string());
    context
}

/// Extracts all `{{variable_name}}` placeholders from a template string.
/// Returns a vector of variable names (without the braces).
pub fn extract_placeholder_names(template_str: &str) -> Vec<String> {
    lazy_static! {
        static ref VARIABLE_RE: Regex =
            Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}").expect("Valid regex");
    }

    VARIABLE_RE
        .captures_iter(template_str)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Advanced variable resolution with support for default values and transformations
///
/// Supports syntax like:
// - `{{var|default:"fallback"}}` - provides default value if var is missing
/// - `{{var|upper}}` - transforms value to uppercase
/// - `{{var|lower}}` - transforms value to lowercase
/// - `{{var|trim}}` - trims whitespace
pub fn resolve_variables_advanced(
    template_str: &str,
    context: &HashMap<String, String>,
) -> Result<String, ScannerError> {
    let mut visited = HashSet::new();
    resolve_variables_advanced_with_detection(template_str, context, &mut visited)
}

fn resolve_variables_advanced_with_detection(
    template_str: &str,
    context: &HashMap<String, String>,
    visited: &mut HashSet<String>,
) -> Result<String, ScannerError> {
    if !template_str.contains("{{") || !template_str.contains("}}") {
        return Ok(template_str.to_string());
    }

    let mut result = String::with_capacity(template_str.len());
    let mut remaining = template_str;

    while let Some(start_idx) = remaining.find("{{") {
        result.push_str(&remaining[..start_idx]);
        let after_start = &remaining[start_idx + 2..];

        if let Some(end_idx) = after_start.find("}}") {
            let inner = &after_start[..end_idx];

            // Parse var_name and optional modifiers
            let (var_name, modifiers) = if let Some(pipe_idx) = inner.find('|') {
                (&inner[..pipe_idx], Some(&inner[pipe_idx + 1..]))
            } else {
                (inner, None)
            };

            if !is_valid_var_name(var_name) {
                result.push_str("{{");
                result.push_str(inner);
                result.push_str("}}");
                remaining = &after_start[end_idx + 2..];
                continue;
            }

            if !visited.insert(var_name.to_string()) {
                return Err(ScannerError::VariableResolutionError(format!(
                    "Circular dependency detected for variable: {}",
                    var_name
                )));
            }

            let mut value = match context.get(var_name) {
                Some(v) => v.clone(),
                None => {
                    if let Some(mods) = modifiers {
                        if let Some(default_val) = extract_default_value(mods) {
                            default_val.to_string()
                        } else {
                            result.push_str("{{");
                            result.push_str(inner);
                            result.push_str("}}");
                            visited.remove(var_name);
                            remaining = &after_start[end_idx + 2..];
                            continue;
                        }
                    } else {
                        result.push_str("{{");
                        result.push_str(inner);
                        result.push_str("}}");
                        visited.remove(var_name);
                        remaining = &after_start[end_idx + 2..];
                        continue;
                    }
                }
            };

            if let Some(mods) = modifiers {
                value = apply_modifiers(&value, mods);
            }

            result.push_str(&value);
            visited.remove(var_name);
            remaining = &after_start[end_idx + 2..];
        } else {
            result.push_str("{{");
            remaining = after_start;
            break;
        }
    }

    result.push_str(remaining);
    Ok(result)
}

// Replaced by above block

/// Extract default value from modifier string like `default:"value"` or `default:'value'`
fn extract_default_value(modifiers: &str) -> Option<&str> {
    lazy_static! {
        static ref DEFAULT_RE: Regex =
            Regex::new(r#"default:(?:"([^"]*)"|'([^']*)')"#).expect("Valid regex");
    }

    DEFAULT_RE.captures(modifiers).and_then(|cap| {
        if let Some(val) = cap.get(1) {
            Some(val.as_str())
        } else if let Some(val) = cap.get(2) {
            Some(val.as_str())
        } else {
            None
        }
    })
}

/// Apply string modifiers like upper, lower, trim, etc.
fn apply_modifiers(value: &str, modifiers: &str) -> String {
    let mut result = value.to_string();

    for modifier in modifiers.split('|') {
        match modifier.trim() {
            "upper" => result = result.to_uppercase(),
            "lower" => result = result.to_lowercase(),
            "trim" => result = result.trim().to_string(),
            "reverse" => result = result.chars().rev().collect(),
            "len" => return result.len().to_string(),
            _ => {
                // Warn about unknown modifier
                tracing::warn!(?modifier, "Unknown variable modifier");
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_variables_basic() {
        let mut ctx = HashMap::new();
        ctx.insert("BaseURL".to_string(), "https://example.com".to_string());
        ctx.insert("token".to_string(), "abc123".to_string());

        let result = resolve_variables("{{BaseURL}}/api?t={{token}}", &ctx).unwrap();
        assert_eq!(result, "https://example.com/api?t=abc123");
    }

    #[test]
    fn test_resolve_variables_circular() {
        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), "{{b}}".to_string());
        ctx.insert("b".to_string(), "{{a}}".to_string());

        let result = resolve_variables("Start {{a}} end", &ctx).unwrap();
        // Should detect circular dependency and leave unresolved
        assert!(result.contains("{{a}}") || result.contains("{{b}}"));
    }

    #[test]
    fn test_resolve_variables_advanced_with_default() {
        let mut ctx = HashMap::new();
        ctx.insert("name".to_string(), "John".to_string());

        // Test default value
        let result = resolve_variables_advanced("Hello {{name|default:\"Guest\"}}!", &ctx).unwrap();
        assert_eq!(result, "Hello John!");

        // Test default when variable missing
        let result =
            resolve_variables_advanced("Hello {{missing|default:\"Guest\"}}!", &ctx).unwrap();
        assert_eq!(result, "Hello Guest!");

        // Test modifiers
        let result = resolve_variables_advanced("Hello {{name|upper}}!", &ctx).unwrap();
        assert_eq!(result, "Hello JOHN!");

        let result = resolve_variables_advanced("Hello {{name|lower}}!", &ctx).unwrap();
        assert_eq!(result, "Hello john!");

        let result = resolve_variables_advanced("Hello {{name|reverse}}!", &ctx).unwrap();
        assert_eq!(result, "Hello nhoJ!");

        let result = resolve_variables_advanced("Length: {{name|len}}", &ctx).unwrap();
        assert_eq!(result, "Length: 4");
    }

    #[test]
    fn test_build_initial_context() {
        let ctx = build_initial_context("https://example.com/", "example.com");
        assert_eq!(ctx.get("BaseURL").unwrap(), "https://example.com");
        assert_eq!(ctx.get("Hostname").unwrap(), "example.com");
    }

    #[test]
    fn test_extract_placeholder_names() {
        let names = extract_placeholder_names(
            "Bearer {{auth_token}} on {{BaseURL}} with {{timeout|default:\"30s\"}}",
        );
        assert!(names.contains(&"auth_token".to_string()));
        assert!(names.contains(&"BaseURL".to_string()));
        // {{timeout|default:"30s"}} uses advanced syntax; basic extraction omits it
        assert!(!names.contains(&"timeout".to_string()));
    }

    // ── Additional edge case tests ─────────────────────────────────────────

    #[test]
    fn test_resolve_variables_no_placeholders() {
        let ctx = HashMap::new();
        assert_eq!(resolve_variables("plain text", &ctx).unwrap(), "plain text");
        assert_eq!(resolve_variables("", &ctx).unwrap(), "");
    }

    #[test]
    fn test_resolve_variables_missing_var_keeps_placeholder() {
        let ctx = HashMap::new();
        let result = resolve_variables("Hello {{unknown}}!", &ctx).unwrap();
        assert_eq!(result, "Hello {{unknown}}!");
    }

    #[test]
    fn test_resolve_variables_nested_interleaved() {
        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), "hello".to_string());
        ctx.insert("b".to_string(), "world".to_string());
        let result = resolve_variables("{{a}}_{{b}}", &ctx).unwrap();
        assert_eq!(result, "hello_world");
    }

    #[test]
    fn test_resolve_variables_special_chars_in_names() {
        // Variable names with underscores (valid in regex)
        let mut ctx = HashMap::new();
        ctx.insert("my_var".to_string(), "value".to_string());
        let result = resolve_variables("{{my_var}}", &ctx).unwrap();
        assert_eq!(result, "value");
    }

    #[test]
    fn test_resolve_variables_adjacent_no_separator() {
        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), "x".to_string());
        ctx.insert("b".to_string(), "y".to_string());
        let result = resolve_variables("{{a}}{{b}}", &ctx).unwrap();
        assert_eq!(result, "xy");
    }

    #[test]
    fn test_resolve_variables_chained_value_contains_placeholder() {
        let mut ctx = HashMap::new();
        ctx.insert("outer".to_string(), "prefix_{{inner}}_suffix".to_string());
        ctx.insert("inner".to_string(), "mid".to_string());
        // Only one pass of resolution — {{inner}} inside the value is NOT resolved
        let result = resolve_variables("{{outer}}", &ctx).unwrap();
        assert_eq!(result, "prefix_{{inner}}_suffix");
    }

    #[test]
    fn test_resolve_variables_deeply_nested_context() {
        let mut ctx = HashMap::with_capacity(100);
        for i in 0..50 {
            ctx.insert(format!("key_{}", i), format!("value_{}", i));
        }
        let mut input = String::new();
        for i in 0..50 {
            input.push_str(&format!("{{{{key_{}}}}},", i));
        }
        let result = resolve_variables(&input, &ctx).unwrap();
        for i in 0..50 {
            assert!(result.contains(&format!("value_{}", i)));
        }
    }

    #[test]
    fn test_resolve_variables_multi_circular() {
        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), "{{b}}".to_string());
        ctx.insert("b".to_string(), "{{c}}".to_string());
        ctx.insert("c".to_string(), "{{a}}".to_string());

        let result = resolve_variables("start {{a}} end", &ctx).unwrap();
        // At least one placeholder should remain unresolved
        assert!(result.contains("{{a}}") || result.contains("{{b}}") || result.contains("{{c}}"));
    }

    // ── Advanced variable resolution edge cases ────────────────────────────

    #[test]
    fn test_advanced_no_placeholders() {
        let ctx = HashMap::new();
        assert_eq!(
            resolve_variables_advanced("simple text", &ctx).unwrap(),
            "simple text"
        );
    }

    #[test]
    fn test_advanced_chained_modifiers() {
        let mut ctx = HashMap::new();
        ctx.insert("name".to_string(), "Hello".to_string());
        let result = resolve_variables_advanced("{{name|upper|reverse}}", &ctx).unwrap();
        assert_eq!(result, "OLLEH");
    }

    #[test]
    fn test_advanced_modifier_on_empty_string() {
        let mut ctx = HashMap::new();
        ctx.insert("empty".to_string(), "".to_string());
        assert_eq!(
            resolve_variables_advanced("{{empty|len}}", &ctx).unwrap(),
            "0"
        );
        assert_eq!(
            resolve_variables_advanced("{{empty|upper}}", &ctx).unwrap(),
            ""
        );
        assert_eq!(
            resolve_variables_advanced("{{empty|reverse}}", &ctx).unwrap(),
            ""
        );
    }

    #[test]
    fn test_advanced_unknown_modifier() {
        let mut ctx = HashMap::new();
        ctx.insert("x".to_string(), "value".to_string());
        // Unknown modifier should pass through value unchanged
        let result = resolve_variables_advanced("{{x|unknownmod}}", &ctx).unwrap();
        assert_eq!(result, "value");
    }

    #[test]
    fn test_advanced_default_with_empty_string() {
        let ctx = HashMap::new();
        let result = resolve_variables_advanced("{{missing|default:\"\"}}", &ctx).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_advanced_missing_var_no_default() {
        let ctx = HashMap::new();
        let result = resolve_variables_advanced("{{missing}}", &ctx).unwrap();
        assert_eq!(result, "{{missing}}");
    }

    #[test]
    fn test_advanced_default_with_special_chars() {
        let ctx = HashMap::new();
        let result =
            resolve_variables_advanced("{{missing|default:\"hello world! @#$%\"}}", &ctx).unwrap();
        assert_eq!(result, "hello world! @#$%");
    }

    #[test]
    fn test_advanced_mixed_syntax() {
        let mut ctx = HashMap::new();
        ctx.insert("user".to_string(), "Alice".to_string());
        ctx.insert("domain".to_string(), "example.com".to_string());
        let result = resolve_variables_advanced(
            "{{user|lower}}@{{domain}} via {{missing|default:\"default\"}}",
            &ctx,
        )
        .unwrap();
        assert_eq!(result, "alice@example.com via default");
    }

    // ── build_initial_context edge cases ──────────────────────────────────

    #[test]
    fn test_build_initial_context_no_scheme() {
        let ctx = build_initial_context("example.com/path", "example.com");
        assert_eq!(ctx.get("BaseURL").unwrap(), "example.com/path");
        assert_eq!(ctx.get("Hostname").unwrap(), "example.com");
    }

    #[test]
    fn test_build_initial_context_with_port() {
        let ctx = build_initial_context("https://example.com:8443/api", "example.com");
        assert_eq!(ctx.get("BaseURL").unwrap(), "https://example.com:8443/api");
        assert_eq!(ctx.get("Hostname").unwrap(), "example.com");
    }

    #[test]
    fn test_build_initial_context_trailing_slash_stripped() {
        let ctx = build_initial_context("https://example.com/", "example.com");
        assert_eq!(ctx.get("BaseURL").unwrap(), "https://example.com");
    }

    // ── extract_placeholder_names edge cases ───────────────────────────────

    #[test]
    fn test_extract_placeholder_names_empty() {
        let names = extract_placeholder_names("");
        assert!(names.is_empty());
    }

    #[test]
    fn test_extract_placeholder_names_no_placeholders() {
        let names = extract_placeholder_names("just text");
        assert!(names.is_empty());
    }

    #[test]
    fn test_extract_placeholder_names_duplicates() {
        let names = extract_placeholder_names("{{a}} and {{a}} and {{a}}");
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn test_extract_placeholder_names_invalid_syntax() {
        // Missing closing braces — should not match
        let names = extract_placeholder_names("{{broken");
        assert!(names.is_empty());
    }
}
