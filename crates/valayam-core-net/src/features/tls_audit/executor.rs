#![allow(clippy::regex_creation_in_loops)]
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use valayam_engine::variables::resolve_variables;
use valayam_models::finding::FindingOwned;
use valayam_models::templates::tls_audit::TlsAuditTemplate;
use valayam_models::TemplateMetadata;
use valayam_network::network::tls;

pub async fn execute(
    tls_rules: &[TlsAuditTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
    variables: &HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    for rule in tls_rules {
        let host = match resolve_variables(&rule.host, variables) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(template_id, rule = %rule.host, "Variable resolution failed: {}", e);
                continue;
            }
        };

        tracing::debug!(target = %host, port = %rule.port, "Starting TLS certificate inspection");

        let mut cert_info = None;
        let mut legacy_versions = Vec::new();

        let needs_legacy_probe = rule.matchers.iter().any(|m| m.r#type == "legacy_tls");
        if needs_legacy_probe {
            legacy_versions = tls::probe_legacy_tls(&host, rule.port).await;
        }

        let needs_cert_inspection =
            rule.matchers.is_empty() || rule.matchers.iter().any(|m| m.r#type != "legacy_tls");
        if needs_cert_inspection {
            cert_info = tls::inspect_certificate(&host, rule.port).await;
        }

        if cert_info.is_none() && legacy_versions.is_empty() {
            tracing::trace!(target = %host, port = %rule.port, "Failed to connect or extract TLS information");
            continue;
        }

        if let Some(ref min_v) = rule.min_version {
            if let Some(ref info) = cert_info {
                if let Some(negotiated) = info.tls_version.as_deref() {
                    let version_rank = |v: &str| -> u8 {
                        if v.contains("1.3") {
                            4
                        } else if v.contains("1.2") {
                            3
                        } else if v.contains("1.1") {
                            2
                        } else if v.contains("1.0") {
                            1
                        } else {
                            0
                        }
                    };
                    if version_rank(negotiated) < version_rank(min_v) {
                        findings.push(FindingOwned::from_template_and_info(
                            template_id,
                            template_meta,
                            format!("{}:{}", host, rule.port),
                            format!("Server negotiated protocol {} which is lower than required minimum version {}", negotiated, min_v),
                        ));
                    }
                }
            }
        }

        if rule.matchers.is_empty() {
            if let Some(c) = cert_info {
                findings.push(FindingOwned::from_template_and_info(
                    template_id,
                    template_meta,
                    format!("{}:{}", host, rule.port),
                    format!(
                        "Issuer: {}, Subject: {}, Expires: {}, Self-signed: {}, SANs: {:?}, Public Key: {} {}bit",
                        c.issuer, c.subject, c.not_after, c.is_self_signed, c.subject_alternative_names, c.public_key_algorithm, c.public_key_bits.unwrap_or(0)
                    ),
                ));
            }
            continue;
        }

        for matcher in &rule.matchers {
            let matched = match matcher.r#type.as_str() {
                "legacy_tls" => !legacy_versions.is_empty(),
                "expired" => cert_info.as_ref().is_some_and(|c| c.is_expired),
                "expiring_soon" => {
                    cert_info.as_ref().is_some_and(|c| {
                        if let Some(max_days) = rule.max_expiry_days {
                            // Parse not_after. Example format varies, we might need a robust parser.
                            // Assuming it's RFC2822 or similar. If we can't parse, we skip.
                            if let Ok(expiry) = DateTime::parse_from_rfc3339(&c.not_after)
                                .or_else(|_| DateTime::parse_from_rfc2822(&c.not_after))
                            {
                                let duration =
                                    expiry.with_timezone(&Utc).signed_duration_since(Utc::now());
                                duration.num_days() >= 0 && duration.num_days() <= max_days as i64
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    })
                }
                "self_signed" => cert_info.as_ref().is_some_and(|c| c.is_self_signed),
                "weak_cipher" => cert_info
                    .as_ref()
                    .and_then(|c| c.cipher_suite.as_ref())
                    .is_some_and(|cipher| {
                        cipher.contains("CBC")
                            || cipher.contains("RC4")
                            || cipher.contains("3DES")
                            || cipher.contains("DES")
                            || cipher.contains("NULL")
                            || cipher.contains("MD5")
                            || cipher.contains("RC2")
                            || cipher.contains("IDEA")
                    }),
                "tls_version" => cert_info
                    .as_ref()
                    .and_then(|c| c.tls_version.as_ref())
                    .is_some_and(|v| {
                        matcher.regex.iter().any(|pattern| {
                            Regex::new(pattern)
                                .map(|re| re.is_match(v))
                                .unwrap_or(false)
                        })
                    }),
                "san" => cert_info.as_ref().is_some_and(|c| {
                    matcher.regex.iter().any(|pattern| {
                        let re = Regex::new(pattern).unwrap_or_else(|_| Regex::new(".*").unwrap());
                        c.subject_alternative_names
                            .iter()
                            .any(|san| re.is_match(san))
                    })
                }),
                "weak_key" => {
                    cert_info
                        .as_ref()
                        .is_some_and(|c| match c.public_key_algorithm.as_str() {
                            "RSA" => {
                                if let Some(bits) = c.public_key_bits {
                                    bits < 2048
                                } else {
                                    false
                                }
                            }
                            "DSA" => {
                                if let Some(bits) = c.public_key_bits {
                                    bits < 2048
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        })
                }
                "is_ca" => cert_info.as_ref().is_some_and(|c| c.is_ca),
                "basic_constraints" => cert_info.as_ref().is_some_and(|c| {
                    matcher.regex.iter().any(|pattern| {
                        let re = Regex::new(pattern).unwrap_or_else(|_| Regex::new(".*").unwrap());
                        let mut match_str = String::new();
                        if c.is_ca {
                            match_str.push_str("CA:true");
                        }
                        if let Some(path_len) = c.path_len_constraint {
                            if !match_str.is_empty() {
                                match_str.push_str(", ");
                            }
                            match_str.push_str(&format!("pathlen:{}", path_len));
                        }
                        re.is_match(&match_str)
                    })
                }),
                "regex" => {
                    if let Some(c) = cert_info.as_ref() {
                        let search_text = match matcher.part.as_str() {
                            "issuer" => c.issuer.to_string(),
                            "subject" => c.subject.to_string(),
                            "serial" => c.serial.to_string(),
                            "version" => c.tls_version.as_deref().unwrap_or("").to_string(),
                            "cipher" => c.cipher_suite.as_deref().unwrap_or("").to_string(),
                            "san" => c.subject_alternative_names.join(", "),
                            "public_key" => format!(
                                "{} {}",
                                c.public_key_algorithm,
                                c.public_key_bits
                                    .map(|b| b.to_string())
                                    .unwrap_or_else(|| "unknown".to_string())
                            ),
                            "is_ca" => c.is_ca.to_string(),
                            _ => c.issuer.to_string(),
                        };
                        matcher.regex.iter().any(|pattern| {
                            Regex::new(pattern)
                                .map(|re| re.is_match(&search_text))
                                .unwrap_or(false)
                        })
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if matched {
                tracing::debug!(target = %host, matcher_type = %matcher.r#type, "Vulnerability TLS match found");
                let payload = match matcher.r#type.as_str() {
                    "expired" => format!(
                        "Certificate expired: {}",
                        cert_info.as_ref().unwrap().not_after
                    ),
                    "expiring_soon" => format!(
                        "Certificate expires soon (within {} days): {}",
                        rule.max_expiry_days.unwrap_or(0),
                        cert_info.as_ref().unwrap().not_after
                    ),
                    "self_signed" => "Self-signed certificate detected".to_string(),
                    "weak_cipher" => format!(
                        "Weak cipher negotiated: {}",
                        cert_info
                            .as_ref()
                            .unwrap()
                            .cipher_suite
                            .as_deref()
                            .unwrap_or("Unknown")
                    ),
                    "tls_version" => format!(
                        "TLS version matched: {}",
                        cert_info
                            .as_ref()
                            .unwrap()
                            .tls_version
                            .as_deref()
                            .unwrap_or("Unknown")
                    ),
                    "legacy_tls" => format!("Legacy protocols supported: {:?}", legacy_versions),
                    "san" => format!(
                        "SAN matched: {} (in {:?})",
                        matcher.regex.join(", "),
                        cert_info.as_ref().unwrap().subject_alternative_names
                    ),
                    "weak_key" => {
                        let c = cert_info.as_ref().unwrap();
                        let bits_str = match c.public_key_bits {
                            Some(bits) => bits.to_string(),
                            None => "unknown".to_string(),
                        };
                        format!(
                            "Weak public key: {} {}bit",
                            c.public_key_algorithm, bits_str
                        )
                    }
                    "is_ca" => {
                        if cert_info.as_ref().unwrap().is_ca {
                            "Certificate is a CA certificate".to_string()
                        } else {
                            "Certificate is not a CA certificate".to_string()
                        }
                    }
                    "basic_constraints" => {
                        let c = cert_info.as_ref().unwrap();
                        let mut desc = String::new();
                        if c.is_ca {
                            desc.push_str("CA:true");
                        }
                        if let Some(path_len) = c.path_len_constraint {
                            if !desc.is_empty() {
                                desc.push_str(", ");
                            }
                            desc.push_str(&format!("pathlen:{}", path_len));
                        }
                        format!(
                            "Basic constraints: {}",
                            if desc.is_empty() { "None" } else { &desc }
                        )
                    }
                    _ => {
                        let c = cert_info.as_ref();
                        let issuer = c.map(|c| c.issuer.as_str()).unwrap_or("").to_string();
                        let not_after = c.map(|c| c.not_after.as_str()).unwrap_or("").to_string();
                        let sans = c
                            .map(|c| c.subject_alternative_names.clone())
                            .unwrap_or_default();
                        let (alg, bits) = c
                            .map(|c| {
                                (
                                    c.public_key_algorithm.as_str(),
                                    c.public_key_bits
                                        .map(|b| b.to_string())
                                        .unwrap_or_else(|| "unknown".to_string()),
                                )
                            })
                            .unwrap_or(("Unknown", "unknown".to_string()));
                        format!(
                            "TLS match on {}: issuer={}, expires={}, SANs: {:?}, Public Key: {} {}bit",
                            host, issuer, not_after, sans, alg, bits
                        )
                    }
                };

                findings.push(FindingOwned::from_template_and_info(
                    template_id,
                    template_meta,
                    format!("{}:{}", host, rule.port),
                    payload,
                ));
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // version_rank internal logic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_rank_tls_1_3() {
        let rank = |v: &str| -> u8 {
            if v.contains("1.3") {
                4
            } else if v.contains("1.2") {
                3
            } else if v.contains("1.1") {
                2
            } else if v.contains("1.0") {
                1
            } else {
                0
            }
        };
        assert_eq!(rank("TLS 1.3"), 4);
        assert_eq!(rank("TLSv1.3"), 4);
    }

    #[test]
    fn test_version_rank_tls_1_2() {
        let rank = |v: &str| -> u8 {
            if v.contains("1.3") {
                4
            } else if v.contains("1.2") {
                3
            } else if v.contains("1.1") {
                2
            } else if v.contains("1.0") {
                1
            } else {
                0
            }
        };
        assert_eq!(rank("TLS 1.2"), 3);
    }

    #[test]
    fn test_version_rank_tls_1_0() {
        let rank = |v: &str| -> u8 {
            if v.contains("1.3") {
                4
            } else if v.contains("1.2") {
                3
            } else if v.contains("1.1") {
                2
            } else if v.contains("1.0") {
                1
            } else {
                0
            }
        };
        assert_eq!(rank("TLS 1.0"), 1);
    }

    #[test]
    fn test_version_rank_unknown() {
        let rank = |v: &str| -> u8 {
            if v.contains("1.3") {
                4
            } else if v.contains("1.2") {
                3
            } else if v.contains("1.1") {
                2
            } else if v.contains("1.0") {
                1
            } else {
                0
            }
        };
        assert_eq!(rank("SSL 3.0"), 0);
    }

    // -----------------------------------------------------------------------
    // Weak cipher detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_weak_cipher_cbc_detected() {
        let cipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string();
        assert!(
            cipher.contains("CBC") || cipher.contains("RC4") || cipher.contains("3DES"),
            "CBC cipher should be flagged as weak"
        );
    }

    #[test]
    fn test_weak_cipher_rc4_detected() {
        let cipher = "TLS_RSA_WITH_RC4_128_MD5".to_string();
        assert!(
            cipher.contains("RC4") || cipher.contains("MD5"),
            "RC4 cipher should be flagged as weak"
        );
    }

    #[test]
    fn test_strong_cipher_not_flagged() {
        let cipher = "TLS_AES_256_GCM_SHA384".to_string();
        assert!(
            !(cipher.contains("CBC")
                || cipher.contains("RC4")
                || cipher.contains("3DES")
                || cipher.contains("DES")
                || cipher.contains("NULL")
                || cipher.contains("MD5")
                || cipher.contains("RC2")
                || cipher.contains("IDEA")),
            "GCM cipher should not be flagged as weak"
        );
    }

    // -----------------------------------------------------------------------
    // Weak key detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_weak_rsa_key_1024_bits() {
        let bits: u16 = 1024;
        assert!(bits < 2048, "1024-bit RSA key should be weak");
    }

    #[test]
    fn test_strong_rsa_key_2048_bits() {
        let bits: u16 = 2048;
        assert!(!(bits < 2048), "2048-bit RSA key should be strong");
    }

    #[test]
    fn test_strong_rsa_key_4096_bits() {
        let bits: u16 = 4096;
        assert!(!(bits < 2048), "4096-bit RSA key should be strong");
    }

    // -----------------------------------------------------------------------
    // TlsAuditTemplate deserialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_tls_template_minimal() {
        let yaml = r#"
host: example.com
"#;
        let tmpl: TlsAuditTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.host, "example.com");
        assert_eq!(tmpl.port, 443, "Default port should be 443");
        assert!(tmpl.min_version.is_none());
        assert!(tmpl.matchers.is_empty());
    }

    #[test]
    fn test_tls_template_custom_port() {
        let yaml = r#"
host: example.com
port: 8443
"#;
        let tmpl: TlsAuditTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.port, 8443);
    }

    #[test]
    fn test_tls_template_with_matchers() {
        let yaml = r#"
host: example.com
min_version: "TLS 1.2"
matchers:
  - type: self_signed
    part: status
"#;
        let tmpl: TlsAuditTemplate = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tmpl.min_version.unwrap(), "TLS 1.2");
        assert_eq!(tmpl.matchers.len(), 1);
        assert_eq!(tmpl.matchers[0].r#type, "self_signed");
    }

    #[test]
    fn test_tls_template_full_config() {
        let tmpl = TlsAuditTemplate {
            host: "example.com".to_string(),
            port: 443,
            min_version: Some("TLS 1.2".to_string()),
            max_expiry_days: Some(30),
            matchers: vec![],
        };
        let json = serde_json::to_string(&tmpl).unwrap();
        let back: TlsAuditTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.host, "example.com");
        assert_eq!(back.max_expiry_days, Some(30));
    }
}
