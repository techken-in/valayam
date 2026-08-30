use crate::network::http::StealthHttpClient;
use std::collections::HashMap;
use valayam_models::{
    finding::FindingOwned,
    templates::{
        auth_logic::{AuthTemplate, LogicTemplate},
        schema::TemplateMetadata,
    },
};

pub async fn execute(
    client: &StealthHttpClient,
    target: &str,
    auth: &Option<AuthTemplate>,
    logic_sections: &[LogicTemplate],
    template_id: &str,
    info: &dyn TemplateMetadata,
    vars: &mut HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    if let Some(auth_config) = auth {
        if auth_config.primary.is_empty() || auth_config.secondary.is_empty() {
            return findings;
        }

        let parse_auth = |s: &str| -> HashMap<String, String> {
            let mut hdrs = HashMap::new();
            if let Some((k, v)) = s.split_once(':') {
                hdrs.insert(k.trim().to_string(), v.trim().to_string());
            } else {
                hdrs.insert("Authorization".to_string(), format!("Bearer {}", s.trim()));
            }
            hdrs
        };

        let secondary_headers = parse_auth(&auth_config.secondary);

        for logic in logic_sections {
            if logic.r#type == "idor" || logic.r#type == "bfla" {
                // For dual mode testing, we attempt to access the resource with the secondary headers
                let mut path = logic.path.clone();
                for (k, v) in vars.iter() {
                    path = path.replace(&format!("{{{{{}}}}}", k), v);
                }

                let url = if path.starts_with("http") {
                    path.clone()
                } else {
                    format!("{}{}", target.trim_end_matches('/'), path)
                };

                if let Ok(resp) = client
                    .send_request(
                        &logic.method,
                        &url,
                        Some(&secondary_headers),
                        None,
                        Some(true),
                        None,
                    )
                    .await
                {
                    let status = resp.status().as_u16();
                    if let Ok(body_bytes) = resp.bytes().await {
                        let text = String::from_utf8_lossy(&body_bytes);

                        let mut matched = false;
                        for matcher in &logic.matchers {
                            if matcher.r#type == "status"
                                && matcher
                                    .status
                                    .as_ref()
                                    .map(|s| s.contains(&status))
                                    .unwrap_or(false)
                            {
                                matched = true;
                            }
                            if matcher.r#type == "word"
                                && matcher.words.iter().any(|w| text.contains(w))
                            {
                                matched = true;
                            }
                        }

                        if matched || (logic.matchers.is_empty() && status >= 200 && status < 300) {
                            let mut f = FindingOwned::from_template_and_info(
                                template_id,
                                info,
                                target.to_string(),
                                url.clone(),
                            );
                            f.protocol = Some("http".to_string());
                            let evidence_req = format!(
                                "{} {} HTTP/1.1\nSecondary-Auth-Used: true",
                                logic.method, url
                            );
                            let evidence_resp = format!("HTTP/1.1 {}\n\n{}", status, text);

                            f.evidence_request = Some(evidence_req);

                            f.evidence_response = Some(if evidence_resp.len() > 2048 {
                                format!("{}... [truncated]", &evidence_resp[..2048])
                            } else {
                                evidence_resp
                            });
                            findings.push(f);
                        }
                    }
                }
            }
        }
    }

    findings
}
