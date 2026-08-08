use valayam_plugin_sdk::{export_plugin, host_funcs, Finding, WasmInput, WasmOutput, WasmScanner};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

const SPAMHAUS_DROP_CIDRS: &[&str] = &[
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/12",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
];

const SPAMHAUS_EDROP_CIDRS: &[&str] = &[
    "23.20.0.0/14", "23.21.0.0/16", "23.22.0.0/15", "50.16.0.0/14",
    "50.17.0.0/16", "52.0.0.0/11", "52.8.0.0/13", "54.0.0.0/11",
    // truncated for brevity...
];

const KNOWN_MALICIOUS_IPS: &[&str] = &[
    "5.188.62.10", "45.142.215.47", "192.210.67.98"
];

const KNOWN_MALICIOUS_DOMAINS: &[&str] = &[
    "malicious-test.com", "phishing.local", "botnet-c2.net", "evil.test"
];

const DNSBL_ZONES: &[&str] = &[
    "zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net",
];

fn ipv4_in_prefix(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 { return true; }
    let ip_bits = u32::from(ip);
    let net_bits = u32::from(network);
    let mask = if prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
    (ip_bits & mask) == (net_bits & mask)
}

fn ipv6_in_prefix(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 { return true; }
    let ip_bits = u128::from(ip);
    let net_bits = u128::from(network);
    let mask = if prefix >= 128 { u128::MAX } else { u128::MAX << (128 - prefix) };
    (ip_bits & mask) == (net_bits & mask)
}

fn ip_in_known_cidrs(ip: IpAddr) -> bool {
    let all_cidrs: Vec<&str> = SPAMHAUS_DROP_CIDRS.iter().chain(SPAMHAUS_EDROP_CIDRS.iter()).copied().collect();
    for cidr_str in &all_cidrs {
        if let Some((base_str, prefix_len)) = cidr_str.split_once('/') {
            if let Ok(network_addr) = IpAddr::from_str(base_str) {
                let prefix: u8 = prefix_len.parse().unwrap_or(32);
                match (network_addr, ip) {
                    (IpAddr::V4(net), IpAddr::V4(test_ip)) => {
                        if ipv4_in_prefix(test_ip, net, prefix) { return true; }
                    }
                    (IpAddr::V6(net), IpAddr::V6(test_ip)) if ipv6_in_prefix(test_ip, net, prefix) => {
                        return true;
                    }
                    _ => {}
                }
            }
        }
    }
    false
}

fn ip_in_known_malicious_ips(ip: IpAddr) -> bool {
    KNOWN_MALICIOUS_IPS.contains(&ip.to_string().as_str())
}

fn domain_in_known_malicious_domains(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    KNOWN_MALICIOUS_DOMAINS.iter().any(|&bad| lower == bad || lower.ends_with(&format!(".{}", bad)))
}

fn is_suspicious_tld(domain: &str) -> bool {
    let suspicious_tlds: &[&str] = &[".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"];
    let lower = domain.to_ascii_lowercase();
    suspicious_tlds.iter().any(|&tld| lower.ends_with(tld))
}

fn check_dnsbl(ip: IpAddr, zone: &str) -> bool {
    let reversed = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0], zone)
        }
        IpAddr::V6(_) => return false,
    };

    // Use our valayam SDK host function for DNS!
    if let Some(ips) = host_funcs::resolve_dns(&reversed) {
        // If it resolves to a loopback address (e.g. 127.0.0.2), it's listed
        return ips.iter().any(|a| a.starts_with("127."));
    }
    false
}

#[derive(Default)]
pub struct ReputationAuditScanner;

impl WasmScanner for ReputationAuditScanner {
    fn scan(&self, input: WasmInput) -> Result<WasmOutput, extism_pdk::Error> {
        let mut findings = Vec::new();
        let template_id = input.template.get("id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let template_name = input.template.get("info").and_then(|i| i.get("name")).and_then(|v| v.as_str()).unwrap_or("Reputation Audit").to_string();
        
        let target = input.context.get("BaseURL").cloned().unwrap_or_else(|| "http://localhost".to_string());
        
        let target_str = target.trim().trim_start_matches("http://").trim_start_matches("https://").trim_start_matches("www.").trim_end_matches('/');
        let target_str = target_str.split(':').next().unwrap_or(target_str).to_string();
        
        let maybe_ip = IpAddr::from_str(&target_str).ok();
        
        let ips = if let Some(ip) = maybe_ip {
            vec![ip]
        } else {
            // resolve domain via host function
            let resolved = host_funcs::resolve_dns(&target_str).unwrap_or_default();
            resolved.iter().filter_map(|s| IpAddr::from_str(s).ok()).collect()
        };

        let mut blocked_by_ip = false;
        let mut blocked_by_domain = false;
        let mut dnsbl_listed = false;
        let mut _dnsbl_count = 0usize;

        for &ip in &ips {
            if ip_in_known_malicious_ips(ip) || ip_in_known_cidrs(ip) {
                blocked_by_ip = true;
                break;
            }
        }

        if domain_in_known_malicious_domains(&target_str) {
            blocked_by_domain = true;
        }

        if !blocked_by_ip {
            for &ip in &ips {
                for zone in DNSBL_ZONES {
                    if check_dnsbl(ip, zone) {
                        dnsbl_listed = true;
                        _dnsbl_count += 1;
                    }
                }
            }
        }

        let has_suspicious_tld = is_suspicious_tld(&target_str);
        
        let mut raw_score: u8 = 0;
        if blocked_by_ip || blocked_by_domain {
            raw_score = 100;
        } else {
            if dnsbl_listed { raw_score = raw_score.saturating_add(60); }
            if has_suspicious_tld { raw_score = raw_score.saturating_add(20); }
        }

        let final_score = raw_score.min(100);

        if final_score >= 30 || blocked_by_ip || blocked_by_domain {
            let mut f = Finding {
                template_id,
                template_name,
                severity: if final_score > 75 { "High".to_string() } else { "Medium".to_string() },
                target: target.clone(),
                matched_at: target_str.clone(),
                description: Some(format!("Reputation score: {}/100. Target shows suspicious characteristics.", final_score)),
                solution: Some("Review network connections to this target. If it is a C2 / phishing domain, block at the firewall level.".to_string()),
                extracted_data: None,
                metadata: std::collections::HashMap::new(),
            };
            f.metadata.insert("recon".to_string(), "Threat Intelligence".to_string());
            findings.push(f);
        }

        Ok(WasmOutput {
            matched: !findings.is_empty(),
            count: findings.len(),
            findings,
        })
    }
}

export_plugin!(ReputationAuditScanner);
