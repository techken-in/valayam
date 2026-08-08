//! Concrete Matcher implementations operating on zero-copy &[u8] buffers.

use super::traits::Matcher;

/// Regex matcher on raw bytes — no UTF-8 conversion.
pub struct RegexMatcher {
    patterns: Vec<regex::bytes::Regex>,
    label: String,
}

impl RegexMatcher {
    /// Create from pattern strings. Invalid patterns are logged and skipped.
    pub fn new(patterns: &[String]) -> Self {
        let compiled: Vec<_> = patterns
            .iter()
            .filter_map(|p| {
                regex::bytes::Regex::new(p)
                    .inspect_err(
                        |e| tracing::warn!(pattern = %p, error = %e, "invalid regex, skipping"),
                    )
                    .ok()
            })
            .collect();
        Self {
            patterns: compiled,
            label: "regex".to_string(),
        }
    }
}

impl Matcher for RegexMatcher {
    fn evaluate(&self, buf: &[u8]) -> bool {
        self.patterns.iter().any(|re| re.is_match(buf))
    }
    fn name(&self) -> &str {
        &self.label
    }
}

/// HTTP status code matcher.
pub struct StatusMatcher {
    allowed: Vec<u16>,
}

impl StatusMatcher {
    /// Documentation for this item.
    pub fn new(statuses: Vec<u16>) -> Self {
        Self { allowed: statuses }
    }
    /// Documentation for this item.
    pub fn matches_status(&self, status: u16) -> bool {
        self.allowed.contains(&status)
    }
}

impl Matcher for StatusMatcher {
    fn evaluate(&self, _buf: &[u8]) -> bool {
        false
    } // Use matches_status() directly
    fn name(&self) -> &str {
        "status"
    }
}

/// Fast byte-level substring search.
pub struct WordMatcher {
    words: Vec<Vec<u8>>,
}

impl WordMatcher {
    /// Documentation for this item.
    pub fn new(words: Vec<String>) -> Self {
        Self {
            words: words.into_iter().map(|w| w.into_bytes()).collect(),
        }
    }
}

impl Matcher for WordMatcher {
    fn evaluate(&self, buf: &[u8]) -> bool {
        self.words
            .iter()
            .any(|w| buf.windows(w.len()).any(|win| win == w.as_slice()))
    }
    fn name(&self) -> &str {
        "word"
    }
}

/// AND/OR combinator.
/// Documentation for this item.
pub enum MatchCondition {
    /// All matchers must pass.
    And,
    /// At least one matcher must pass.
    Or,
}

/// Documentation for this item.
pub struct CompositeMatcher {
    matchers: Vec<Box<dyn Matcher>>,
    condition: MatchCondition,
}

impl CompositeMatcher {
    /// Documentation for this item.
    pub fn new(matchers: Vec<Box<dyn Matcher>>, condition: MatchCondition) -> Self {
        Self {
            matchers,
            condition,
        }
    }
}

impl Matcher for CompositeMatcher {
    fn evaluate(&self, buf: &[u8]) -> bool {
        match self.condition {
            MatchCondition::And => self.matchers.iter().all(|m| m.evaluate(buf)),
            MatchCondition::Or => self.matchers.iter().any(|m| m.evaluate(buf)),
        }
    }
    fn name(&self) -> &str {
        "composite"
    }
}

#[cfg(test)]
mod tests {
    use super::super::traits::Matcher as MatcherTrait;
    use super::*;

    // ── RegexMatcher tests ─────────────────────────────────────────────────

    #[test]
    fn test_regex_matcher_matches_body() {
        let matcher = RegexMatcher::new(&["admin".to_string(), "root".to_string()]);
        assert!(matcher.evaluate(b"The admin page is here"));
        assert!(matcher.evaluate(b"root login detected"));
        assert!(!matcher.evaluate(b"user page"));
    }

    #[test]
    fn test_regex_matcher_empty_patterns_never_match() {
        let matcher = RegexMatcher::new(&[]);
        assert!(!matcher.evaluate(b"anything"));
    }

    #[test]
    fn test_regex_matcher_invalid_pattern_skipped() {
        // Invalid regex should be logged and skipped — should never match
        let matcher = RegexMatcher::new(&[r"[invalid".to_string()]);
        assert!(!matcher.evaluate(b"anything"));
    }

    #[test]
    fn test_regex_matcher_mixed_valid_invalid() {
        let matcher = RegexMatcher::new(&[r"[invalid".to_string(), "valid".to_string()]);
        assert!(matcher.evaluate(b"this is valid"));
        assert!(!matcher.evaluate(b"nothing here"));
    }

    #[test]
    fn test_regex_matcher_case_sensitive() {
        let matcher = RegexMatcher::new(&["secret".to_string()]);
        assert!(matcher.evaluate(b"contains secret data"));
        assert!(!matcher.evaluate(b"contains SECRET data"));
    }

    #[test]
    fn test_regex_matcher_binary_data() {
        let matcher = RegexMatcher::new(&[r"\x00\x01\x02".to_string()]);
        assert!(matcher.evaluate(b"\x00\x01\x02\x03"));
        assert!(!matcher.evaluate(b"\x00\x00\x00\x00"));
    }

    #[test]
    fn test_regex_matcher_utf8_pattern() {
        let matcher = RegexMatcher::new(&[r"\p{L}+".to_string()]);
        assert!(matcher.evaluate("hello".as_bytes()));
        assert!(matcher.evaluate("café".as_bytes()));
    }

    #[test]
    fn test_regex_matcher_name() {
        let matcher = RegexMatcher::new(&["test".to_string()]);
        assert_eq!(matcher.name(), "regex");
    }

    // ── StatusMatcher tests ────────────────────────────────────────────────

    #[test]
    fn test_status_matcher_matches() {
        let matcher = StatusMatcher::new(vec![200, 201, 204]);
        assert!(matcher.matches_status(200));
        assert!(matcher.matches_status(204));
        assert!(!matcher.matches_status(404));
        assert!(!matcher.matches_status(500));
    }

    #[test]
    fn test_status_matcher_empty() {
        let matcher = StatusMatcher::new(vec![]);
        assert!(!matcher.matches_status(200));
    }

    #[test]
    fn test_status_matcher_name() {
        let matcher = StatusMatcher::new(vec![200]);
        assert_eq!(matcher.name(), "status");
    }

    // ── WordMatcher tests ──────────────────────────────────────────────────

    #[test]
    fn test_word_matcher_exact_match() {
        let matcher = WordMatcher::new(vec!["secret".to_string(), "password".to_string()]);
        assert!(matcher.evaluate(b"the secret is out"));
        assert!(matcher.evaluate(b"your password: 1234"));
        assert!(!matcher.evaluate(b"nothing sensitive"));
    }

    #[test]
    fn test_word_matcher_partial_word() {
        let matcher = WordMatcher::new(vec!["pass".to_string()]);
        assert!(matcher.evaluate(b"password"));
        assert!(matcher.evaluate(b"passphrase"));
        assert!(!matcher.evaluate(b"wrodpss")); // doesn't contain "pass" as substring
    }

    #[test]
    fn test_word_matcher_binary() {
        let matcher = WordMatcher::new(vec!["MZ".to_string()]);
        assert!(matcher.evaluate(b"MZ\x90\x00\x03"));
        assert!(!matcher.evaluate(b"hello world"));
    }

    #[test]
    fn test_word_matcher_empty_words() {
        let matcher = WordMatcher::new(vec![]);
        assert!(!matcher.evaluate(b"anything"));
    }

    #[test]
    fn test_word_matcher_name() {
        let matcher = WordMatcher::new(vec!["a".to_string()]);
        assert_eq!(matcher.name(), "word");
    }

    // ── CompositeMatcher tests ─────────────────────────────────────────────

    fn regex_matcher(pattern: &str) -> Box<dyn Matcher> {
        Box::new(RegexMatcher::new(&[pattern.to_string()]))
    }

    #[test]
    fn test_composite_and_all_match() {
        let composite = CompositeMatcher::new(
            vec![regex_matcher("admin"), regex_matcher("login")],
            MatchCondition::And,
        );
        assert!(composite.evaluate(b"admin login page"));
        assert!(!composite.evaluate(b"admin only")); // missing "login"
        assert!(!composite.evaluate(b"login only")); // missing "admin"
    }

    #[test]
    fn test_composite_or_some_match() {
        let composite = CompositeMatcher::new(
            vec![regex_matcher("error"), regex_matcher("warning")],
            MatchCondition::Or,
        );
        assert!(composite.evaluate(b"got an error"));
        assert!(composite.evaluate(b"just a warning"));
        assert!(!composite.evaluate(b"all good"));
    }

    #[test]
    fn test_composite_and_mixed_types() {
        let word_matcher: Box<dyn Matcher> = Box::new(WordMatcher::new(vec!["secret".to_string()]));
        let regex_matcher: Box<dyn Matcher> = Box::new(RegexMatcher::new(&["key\\d+".to_string()]));
        let composite =
            CompositeMatcher::new(vec![word_matcher, regex_matcher], MatchCondition::And);
        assert!(composite.evaluate(b"contains secret and key123"));
        assert!(!composite.evaluate(b"contains secret only")); // no key\d+ match
        assert!(!composite.evaluate(b"key456 without anything")); // no "secret" match
    }

    #[test]
    fn test_composite_empty_matchers() {
        let composite = CompositeMatcher::new(vec![], MatchCondition::And);
        // Empty AND: all(0) matchers pass
        assert!(composite.evaluate(b"anything"));

        let composite = CompositeMatcher::new(vec![], MatchCondition::Or);
        // Empty OR: any(0) matchers pass
        assert!(!composite.evaluate(b"anything"));
    }

    #[test]
    fn test_composite_name() {
        let composite = CompositeMatcher::new(vec![regex_matcher("test")], MatchCondition::And);
        assert_eq!(composite.name(), "composite");
    }

    // ── Integration tests ──────────────────────────────────────────────────

    #[test]
    fn test_match_against_realistic_http_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome admin</body></html>";

        let admin_matcher = RegexMatcher::new(&["admin".to_string()]);
        assert!(admin_matcher.evaluate(response));

        let status_matcher = StatusMatcher::new(vec![200]);
        // StatusMatcher.evaluate(&[u8]) always returns false — use matches_status()
        assert!(!status_matcher.evaluate(response));
        assert!(status_matcher.matches_status(200));
    }

    #[test]
    fn test_word_vs_regex_performance_indicator() {
        // For simple literal matching, WordMatcher should be functionally equivalent
        let word = WordMatcher::new(vec!["simple".to_string()]);
        let regex = RegexMatcher::new(&["simple".to_string()]);

        assert_eq!(
            word.evaluate(b"simple text"),
            regex.evaluate(b"simple text")
        );
        assert_eq!(word.evaluate(b"no match"), regex.evaluate(b"no match"));
    }
}
