use valayam_models::{
    finding::FindingOwned,
    templates::{
        schema::TemplateMetadata,
        graphql_audit::GraphqlAuditTemplate,
    },
};
use crate::network::http::StealthHttpClient;
use std::collections::HashMap;

pub async fn execute(
    client: &StealthHttpClient,
    target: &str,
    sections: &[GraphqlAuditTemplate],
    template_id: &str,
    info: &dyn TemplateMetadata,
    _vars: &mut HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    for section in sections {
        if section.introspection {
            let introspection_query = r#"{"query":"\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n      }\n    }\n  "}"#;
            
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            
            if let Ok(resp) = client.send_request("POST", &section.target, Some(&headers), Some(introspection_query), Some(true), None).await {
                if let Ok(body) = resp.text().await {
                    if body.contains("__schema") && body.contains("queryType") {
                        let mut f = FindingOwned::from_template_and_info(
                            template_id,
                            info,
                            target.to_string(),
                            section.target.clone(),
                        );
                        f.protocol = Some("graphql".to_string());
                        f.evidence_request = Some(introspection_query.to_string());
                        
                        let evidence_body = if body.len() > 2048 {
                            format!("{}... [truncated]", &body[..2048])
                        } else {
                            body.clone()
                        };
                        f.evidence_response = Some(evidence_body);
                        findings.push(f);
                    }
                }
            }
        }
    }

    findings
}
