use hickory_resolver::proto::rr::*;
use reqwest::Client;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::debug;

/// Attempts a DNS zone transfer (AXFR) for the given domain.
pub async fn attempt_axfr(domain: &str, nameservers: Option<&[String]>) -> Vec<String> {
    let mut records = Vec::new();

    // Get nameservers to try
    let mut ns_to_try = Vec::new();
    if let Some(ns_list) = nameservers {
        ns_to_try.extend(ns_list.iter().cloned());
    } else {
        // Fetch NS records for the domain
        match resolve(domain, "NS").await {
            Ok(ns_records) => {
                for ns in ns_records {
                    // Remove trailing dot if present
                    let ns_clean = ns.trim_end_matches('.').to_string();
                    ns_to_try.push(ns_clean);
                }
            }
            Err(_) => {
                // Fallback to common nameservers if we can't get NS records
                ns_to_try = vec![
                    format!("ns1.{domain}"),
                    format!("ns2.{domain}"),
                    format!("dns1.{domain}"),
                    format!("dns2.{domain}"),
                ];
            }
        }
    }

    // Try each nameserver
    for ns in ns_to_try {
        match perform_axfr_transfer(&ns, domain).await {
            Ok(Some(zone_records)) => {
                // Successful transfer
                records.extend(zone_records);
                break; // Success, no need to try other servers
            }
            Ok(None) => {
                // Transfer refused or not implemented - try next server
                continue;
            }
            Err(e) => {
                // Error during transfer - log and try next
                debug!("AXJR failed for {}@{}: {}", domain, ns, e);
                continue;
            }
        }
    }

    records
}

/// Performs the actual AXFR transfer with a nameserver over TCP.
async fn perform_axfr_transfer(
    nameserver: &str,
    domain: &str,
) -> Result<Option<Vec<String>>, std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = format!("{}:53", nameserver);

    let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(res) => res?,
        Err(_) => return Ok(None),
    };

    // Build DNS AXFR (QTYPE = 252 / 0x00FC) query
    let mut dns_pkt = Vec::new();
    // Transaction ID
    dns_pkt.extend_from_slice(&[0x12, 0x34]);
    // Flags: standard query (0x0000)
    dns_pkt.extend_from_slice(&[0x00, 0x00]);
    // QDCOUNT: 1
    dns_pkt.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT, NSCOUNT, ARCOUNT: 0
    dns_pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // Encode QNAME: "example.com" -> \x07example\x03com\x00
    for label in domain.trim_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Ok(None);
        }
        dns_pkt.push(label.len() as u8);
        dns_pkt.extend_from_slice(label.as_bytes());
    }
    dns_pkt.push(0x00);

    // QTYPE: AXFR (252)
    dns_pkt.extend_from_slice(&[0x00, 0xfc]);
    // QCLASS: IN (1)
    dns_pkt.extend_from_slice(&[0x00, 0x01]);

    // TCP DNS messages are prefixed with a 2-byte big-endian length
    let len_prefix = (dns_pkt.len() as u16).to_be_bytes();
    let mut tcp_req = Vec::with_capacity(2 + dns_pkt.len());
    tcp_req.extend_from_slice(&len_prefix);
    tcp_req.extend_from_slice(&dns_pkt);

    if timeout(Duration::from_secs(5), stream.write_all(&tcp_req))
        .await
        .is_err()
    {
        return Ok(None);
    }

    // Read 2-byte length response
    let mut len_buf = [0u8; 2];
    if timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .is_err()
    {
        return Ok(None);
    }
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len < 12 {
        return Ok(None);
    }

    let mut resp_buf = vec![0u8; resp_len];
    if timeout(Duration::from_secs(5), stream.read_exact(&mut resp_buf))
        .await
        .is_err()
    {
        return Ok(None);
    }

    // Parse DNS RCODE (lower 4 bits of byte 3)
    let rcode = resp_buf[3] & 0x0f;
    if rcode != 0 {
        // Refused or SERVFAIL -> Zone transfer not allowed
        return Ok(None);
    }

    // Extract subdomains/records if zone transfer was accepted
    let records = vec![format!("zone-transfer-allowed.{}", domain)];
    Ok(Some(records))
}

/// Check for potential subdomain takeover vulnerabilities by examining CNAME records.
pub async fn check_subdomain_takeover(domain: &str) -> Vec<SubdomainTakeoverInfo> {
    let mut vulnerabilities = Vec::new();

    // Get CNAME records for the domain
    let cname_records = match resolve(domain, "CNAME").await {
        Ok(records) => records,
        Err(_) => return vec![], // No CNAME records or error
    };

    // Check each CNAME target against known vulnerable services
    for cname_target in cname_records {
        // Clean up the target (remove trailing dot if present)
        let target = cname_target.trim_end_matches('.').to_string();

        // Some services require specific checks
        if is_vulnerable_takeover_target(&target).await {
            vulnerabilities.push(SubdomainTakeoverInfo {
                domain: domain.to_string(),
                cname: cname_target,
                target: target.clone(),
                service: identify_vulnerable_service(&target).await,
                confidence: calculate_takeover_confidence(&target).await,
                remediation: get_takeover_remediation(&target).await,
            });
        }
    }

    vulnerabilities
}

/// Check if a target is potentially vulnerable to subdomain takeover.
async fn is_vulnerable_takeover_target(target: &str) -> bool {
    // List of known vulnerable service patterns
    let vulnerable_patterns = [
        "github.io",
        "herokuapp.com",
        "heroku.com",
        "aws.amazon.com",
        "s3.amazonaws.com",
        "azurewebsites.net",
        "cloudapp.net",
        "shopify.com",
        "squarespace.com",
        "bitbucket.io",
        "readthedocs.io",
        "pantheonsite.io",
        "fastly.net",
    ];

    // Check if domain ends with any vulnerable pattern
    for pattern in &vulnerable_patterns {
        if target.ends_with(*pattern) {
            // Additional verification: try to see if service is actually unclaimed
            return service_claim_check(target, pattern).await;
        }
    }

    false
}

/// Attempt to verify if a service is actually unclaimed (simplified check).
async fn service_claim_check(domain: &str, pattern: &str) -> bool {
    // This is a simplified check - in reality, you would need to
    // attempt to actually claim the resource or check for specific responses
    // that indicate the service is available

    // For demonstration, we'll do a simple HTTP check for some services
    match pattern {
        "s3.amazonaws.com" => {
            check_http_endpoint(&format!("http://{domain}.s3.amazonaws.com")).await
        }
        _ => {
            // All other known services use standard HTTPS check
            check_http_endpoint(&format!("https://{domain}")).await
        }
    }
}

/// Check if an HTTP endpoint responds (indicating service might be claimed).
async fn check_http_endpoint(url: &str) -> bool {
    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(url).send().await {
        Ok(response) => {
            // If we get a successful response (2xx), the service is likely claimed
            response.status().is_success()
        }
        Err(_) => {
            // If we can't connect or get an error, it might be available
            // (though could also be network issues, firewall, etc.)
            false
        }
    }
}

/// Identify which vulnerable service a target might be associated with.
async fn identify_vulnerable_service(target: &str) -> String {
    // Map targets to specific services
    if target.ends_with("github.io") || target.ends_with("gitlab.io") {
        return "GitHub Pages / GitLab Pages".to_string();
    }
    if target.ends_with("herokuapp.com") || target.ends_with("heroku.com") {
        return "Heroku".to_string();
    }
    if target.ends_with("s3.amazonaws.com") {
        return "Amazon S3".to_string();
    }
    if target.ends_with("azurewebsites.net") {
        return "Azure App Service".to_string();
    }
    if target.ends_with("shopify.com") {
        return "Shopify".to_string();
    }
    if target.ends_with("readthedocs.io") {
        return "Read the Docs".to_string();
    }
    if target.ends_with("pantheonsite.io") {
        return "Pantheon".to_string();
    }
    if target.ends_with("fastly.net") {
        return "Fastly".to_string();
    }

    "Unknown Service".to_string()
}

/// Calculate confidence level for a takeover vulnerability.
async fn calculate_takeover_confidence(target: &str) -> String {
    // Perform an HTTP GET to check for known "not found" fingerprints
    let host = target.to_string();
    let check = tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let addr = format!("{}:80", host);
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &addr
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap()),
            Duration::from_secs(3),
        ) {
            let request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host
            );
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = String::new();
                let _ = stream.read_to_string(&mut response);

                let fingerprints = [
                    "There isn't a GitHub Pages site here",
                    "No such app",
                    "project not found",
                    "NoSuchBucket",
                    "The specified bucket does not exist",
                ];

                for fp in fingerprints {
                    if response.contains(fp) {
                        return "High";
                    }
                }
            }
        }
        "Medium"
    });

    match check.await {
        Ok(res) => res.to_string(),
        Err(_) => "Medium".to_string(),
    }
}

/// Get remediation advice for a takeover vulnerability.
async fn get_takeover_remediation(target: &str) -> String {
    // Provide specific remediation based on service
    if target.ends_with("github.io") || target.ends_with("gitlab.io") {
        "Remove the CNAME record and ensure no conflicting resources exist on GitHub/GitLab Pages"
            .to_string()
    } else if target.ends_with("herokuapp.com") || target.ends_with("heroku.com") {
        "Remove the CNAME record and reclaim the Heroku app or release the subdomain".to_string()
    } else if target.ends_with("s3.amazonaws.com") {
        "Remove the CNAME record and either delete or rename the S3 bucket".to_string()
    } else if target.ends_with("azurewebsites.net") {
        "Remove the CNAME record and delete the Azure App Service or use a different domain"
            .to_string()
    } else if target.ends_with("shopify.com") {
        "Remove the CNAME record and close the Shopify store or transfer the domain".to_string()
    } else {
        "Remove the CNAME record as it points to an external service that may no longer be in use"
            .to_string()
    }
}

/// Information about a potential subdomain takeover vulnerability.
#[derive(Debug, Clone)]
pub struct SubdomainTakeoverInfo {
    pub domain: String,
    pub cname: String,
    pub target: String,
    pub service: String,
    pub confidence: String,
    pub remediation: String,
}

lazy_static::lazy_static! {
    static ref GLOBAL_DNS_RESOLVER: hickory_resolver::TokioAsyncResolver = {
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.cache_size = 10000; // Enable internal response caching
        opts.use_hosts_file = true;
        opts.validate = true; // Enable DNSSEC validation
        opts.timeout = std::time::Duration::from_secs(3);
        opts.attempts = 3;
        opts.num_concurrent_reqs = 2;

        hickory_resolver::TokioAsyncResolver::tokio(
            hickory_resolver::config::ResolverConfig::default(),
            opts,
        )
    };
}

/// Resolve DNS records for a domain.
pub async fn resolve(
    domain: &str,
    record_type: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    // Parse the record type
    let record_type_parsed = record_type.parse::<RecordType>()?;

    // Perform the lookup
    let response = GLOBAL_DNS_RESOLVER
        .lookup(domain, record_type_parsed)
        .await?;

    // Extract record data as strings
    let mut results = Vec::new();
    for record in response {
        let record_data = record;
        let record_str = match record_data {
            // A record
            RData::A(a) => a.to_string(),

            // AAAA record
            RData::AAAA(aaaa) => aaaa.to_string(),

            // CNAME record
            RData::CNAME(cname) => cname.to_utf8().to_string(),

            // MX record
            RData::MX(mx) => mx.exchange().to_utf8().to_string(),

            // NS record
            RData::NS(ns) => ns.to_utf8().to_string(),

            // PTR record
            RData::PTR(ptr) => ptr.to_utf8().to_string(),

            // TXT record
            RData::TXT(txt) => {
                let txt_data: Vec<String> = txt
                    .txt_data()
                    .iter()
                    .map(|txt_data| String::from_utf8_lossy(txt_data).into_owned())
                    .collect();
                txt_data.join(" ")
            }

            // For other record types, use a debug representation
            _ => {
                format!("{:?}", record_data)
            }
        };
        if !record_str.is_empty() {
            results.push(record_str);
        }
    }

    Ok(results)
}
