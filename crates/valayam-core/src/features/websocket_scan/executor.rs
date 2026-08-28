use valayam_models::{
    finding::FindingOwned,
    templates::{
        schema::TemplateMetadata,
        websocket::WebsocketTemplate,
    },
};
use std::collections::HashMap;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{SinkExt, StreamExt};
use url::Url;

pub async fn execute(
    target: &str,
    sections: &[WebsocketTemplate],
    template_id: &str,
    info: &dyn TemplateMetadata,
    vars: &mut HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    for section in sections {
        // Construct ws/wss URL from target
        let parsed_target = match Url::parse(target) {
            Ok(u) => u,
            Err(_) => continue,
        };

        let ws_scheme = match parsed_target.scheme() {
            "https" => "wss",
            _ => "ws",
        };

        let ws_url = format!(
            "{}://{}{}",
            ws_scheme,
            parsed_target.host_str().unwrap_or("localhost"),
            parsed_target.path()
        );

        let ws_url = match Url::parse(&ws_url) {
            Ok(u) => u.to_string(),
            Err(_) => continue,
        };

        if let Ok((mut ws_stream, _response)) = connect_async(&ws_url).await {
            let mut matched = false;
            let mut evidence_str = String::new();
            let mut raw_req = String::new();

            for input in &section.inputs {
                let mut payload = input.clone();
                for (k, v) in vars.iter() {
                    payload = payload.replace(&format!("{{{{{}}}}}", k), v);
                }
                
                if let Err(_) = ws_stream.send(Message::Text(payload.clone().into())).await {
                    continue;
                }
                raw_req.push_str(&payload);
                raw_req.push('\n');

                // Wait for response with timeout
                if let Ok(Some(Ok(msg))) = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    ws_stream.next(),
                ).await {
                    let text = msg.to_string();
                    evidence_str.push_str(&text);
                    evidence_str.push('\n');

                    // Check matchers
                    for matcher in &section.matchers {
                        if matcher.r#type == "word" && matcher.words.iter().any(|w| text.contains(w)) {
                            matched = true;
                        }
                    }

                    // Extract variables
                    for extractor in &section.extractors {
                        if extractor.r#type == "regex" {
                            if let Some(pattern) = &extractor.regex {
                                if let Ok(re) = regex::Regex::new(pattern) {
                                    if let Some(caps) = re.captures(&text) {
                                        if let Some(m) = caps.get(extractor.group) {
                                            vars.insert(extractor.name.clone(), m.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if matched {
                let mut f = FindingOwned::from_template_and_info(
                    template_id,
                    info,
                    target.to_string(),
                    "websocket".to_string(),
                );
                f.protocol = Some("websocket".to_string());
                f.evidence_request = Some(raw_req);
                f.evidence_response = Some(evidence_str);
                findings.push(f);
            }
            
            let _ = ws_stream.close(None).await;
        }
    }

    findings
}
