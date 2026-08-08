use regex::Regex;
use std::sync::OnceLock;

/// Represents a detected secret
#[derive(Debug, Clone, PartialEq)]
pub struct SecretMatch {
    pub matched_content: String,
}

static PASSWD_PATTERN: OnceLock<Regex> = OnceLock::new();
static DB_PASSWORD: OnceLock<Regex> = OnceLock::new();
static JSON_ARGS: OnceLock<Regex> = OnceLock::new();
static AWS_ACCESS_KEY: OnceLock<Regex> = OnceLock::new();
static JWT_TOKEN: OnceLock<Regex> = OnceLock::new();
static API_KEY: OnceLock<Regex> = OnceLock::new();
static PRIVATE_KEY: OnceLock<Regex> = OnceLock::new();

/// Check text content against common secret and credential signatures
pub fn detect_secrets(content: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    let patterns = [
        PASSWD_PATTERN.get_or_init(|| Regex::new(r"root:x:[0-9]+:[0-9]+:").expect("static regex")),
        DB_PASSWORD.get_or_init(|| Regex::new(r"(?i)DB_PASSWORD=").expect("static regex")),
        JSON_ARGS.get_or_init(|| Regex::new(r#"\"args\":\s*\{"#).expect("static regex")),
        AWS_ACCESS_KEY.get_or_init(|| Regex::new(r"(?i)AKIA[0-9A-Z]{16}").expect("static regex")),
        JWT_TOKEN.get_or_init(|| {
            Regex::new(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*")
                .expect("static regex")
        }),
        API_KEY.get_or_init(|| {
            Regex::new(r#"(?i)api[_-]?key[\s=:"']+[A-Za-z0-9_=-]+"#).expect("static regex")
        }),
        PRIVATE_KEY.get_or_init(|| {
            Regex::new(r"(?i)BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY").expect("static regex")
        }),
    ];

    for re in &patterns {
        if let Some(m) = re.find(content) {
            matches.push(SecretMatch {
                matched_content: m.as_str().to_string(),
            });
        }
    }

    matches
}
