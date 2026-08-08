use crate::templates::functions;
use regex::Regex;
/// Parses and evaluates all `{{function(arg)}}` helper expressions in a string.
///
/// This is called **after** variable substitution, so expressions like
/// `{{base64({{username}})}}` will have the inner variable already resolved
/// to `{{base64(admin)}}` before this function runs.
///
/// Supported syntax:
/// - `{{function_name(argument)}}` — single argument
/// - Nested parentheses in arguments are not supported
///
/// Unknown function names are left as-is (not resolved).
pub fn evaluate_helpers(input: &str) -> String {
    // Match patterns like {{function_name(argument)}}
    // The regex captures: function_name and argument (everything between parens)
    let re = Regex::new(r"\{\{(\w+)\(([^)]*)\)\}\}").unwrap();

    re.replace_all(input, |caps: &regex::Captures| {
        let func_name = &caps[1];
        let arg = &caps[2];

        match functions::call_helper(func_name, arg) {
            Some(result) => result,
            None => caps[0].to_string(), // Unknown function: leave as-is
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_base64() {
        let result = evaluate_helpers("Basic {{base64(admin:admin)}}");
        assert_eq!(result, "Basic YWRtaW46YWRtaW4=");
    }

    #[test]
    fn test_evaluate_md5() {
        let result = evaluate_helpers("hash={{md5(hello)}}");
        assert_eq!(result, "hash=5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_evaluate_unknown_function() {
        let result = evaluate_helpers("{{unknown_fn(test)}}");
        assert_eq!(result, "{{unknown_fn(test)}}"); // Left as-is
    }

    #[test]
    fn test_evaluate_multiple() {
        let result = evaluate_helpers("{{to_upper(hello)}} {{to_lower(WORLD)}}");
        assert_eq!(result, "HELLO world");
    }

    #[test]
    fn test_no_helpers() {
        let result = evaluate_helpers("plain text with {{variable}}");
        assert_eq!(result, "plain text with {{variable}}");
    }
}
