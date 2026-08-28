use valayam_models::{
    finding::FindingOwned,
    templates::{
        schema::TemplateMetadata,
        subdomain_takeover::SubdomainTakeoverTemplate,
    },
};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use std::collections::HashMap;

pub async fn execute(
    target: &str,
    subdomain_config: &SubdomainTakeoverTemplate,
    template_id: &str,
    info: &dyn TemplateMetadata,
    _vars: &mut HashMap<String, String>,
) -> Vec<FindingOwned> {
    let mut findings = Vec::new();

    let target_domain = if target.starts_with("http") {
        if let Ok(url) = url::Url::parse(target) {
            url.host_str().unwrap_or(target).to_string()
        } else {
            target.to_string()
        }
    } else {
        target.to_string()
    };

    // Use Cloudflare DNS over HTTPS/TLS for the resolver
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = false;
    let config = ResolverConfig::cloudflare(); // Uses DoT

    let resolver = TokioAsyncResolver::tokio(config, opts);

    if let Ok(response) = resolver.lookup_ip(&target_domain).await {
        // Just checking if resolution succeeds and looking at CNAMEs is one approach.
        // For DNS over HTTPS/TLS subdomain takeover, we might look for vulnerable CNAMEs.
    }
    
    // We already have some DNS code in network::dns. Let's use hickory_resolver directly here to look up CNAMEs.
    if let Ok(cname_response) = resolver.lookup(target_domain.clone(), hickory_resolver::proto::rr::RecordType::CNAME).await {
        for record in cname_response.iter() {
            if let Some(cname) = record.as_cname() {
                let target_cname = cname.0.to_string().trim_end_matches('.').to_string();
                
                // Compare with template target
                if target_cname.contains(&subdomain_config.target) {
                    let mut f = FindingOwned::from_template_and_info(
                        template_id,
                        info,
                        target.to_string(),
                        target_domain.clone(),
                    );
                    f.protocol = Some("dns".to_string());
                    f.evidence_request = Some(format!("dig CNAME {}", target_domain));
                    f.evidence_response = Some(format!("CNAME {}", target_cname));
                    
                    findings.push(f);
                }
            }
        }
    }

    findings
}
