#![allow(clippy::if_same_then_else)]
use crate::features::network_scan::parser::parse_port_ranges;
use regex::bytes::Regex;
use std::collections::HashMap;
use valayam_models::finding::FindingOwned;
use valayam_models::templates::network_scan::NetworkRequestTemplate;
use valayam_models::TemplateMetadata;
use valayam_network::network::tcp;
use valayam_network::network::udp;

const SENSITIVE_PORTS: &[u16] = &[
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    135,   // MS RPC
    139,   // NetBIOS
    445,   // SMB
    1433,  // MSSQL
    1434,  // MSSQL Monitor
    1521,  // Oracle
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5900,  // VNC
    5901,  // VNC
    6379,  // Redis
    27017, // MongoDB
    11211, // Memcached
];

fn identify_service_from_banner(port: u16, banner: &str) -> (String, Option<String>) {
    let banner_lower = banner.to_lowercase();

    let (service, version) = match port {
        22 => {
            if banner_lower.contains("ssh") {
                let version = extract_version_from_banner(banner);
                ("SSH".to_string(), version)
            } else {
                ("Unknown".to_string(), None)
            }
        }
        23 => {
            if banner_lower.contains("telnet") {
                ("Telnet".to_string(), None)
            } else {
                ("Unknown".to_string(), None)
            }
        }
        25 => {
            if banner.contains("ESMTP")
                || banner.contains("Sendmail")
                || banner.contains("Postfix")
                || banner.contains("Exim")
                || banner.contains("Exchange")
            {
                let service_name = if banner.contains("Microsoft") || banner.contains("Exchange") {
                    "Microsoft SMTP"
                } else if banner.contains("Sendmail") {
                    "Sendmail"
                } else if banner.contains("Postfix") {
                    "Postfix"
                } else if banner.contains("Exim") {
                    "Exim"
                } else {
                    "SMTP Server"
                };
                (
                    service_name.to_string(),
                    extract_version_from_banner(banner),
                )
            } else if banner_lower.contains("smtp") || banner_lower.contains("mail") {
                ("SMTP".to_string(), extract_version_from_banner(banner))
            } else {
                ("SMTP".to_string(), None)
            }
        }
        53 => {
            if banner_lower.contains("dns") || banner.contains("named") {
                ("DNS".to_string(), extract_version_from_banner(banner))
            } else {
                ("DNS".to_string(), None)
            }
        }
        135 => {
            if banner_lower.contains("msrpc") || banner.contains("Microsoft RPC") {
                ("MSRPC".to_string(), extract_version_from_banner(banner))
            } else {
                ("MSRPC".to_string(), None)
            }
        }
        139 | 445 => {
            if banner.contains("Samba") {
                ("SMB".to_string(), extract_version_from_banner(banner))
            } else if banner.contains("Microsoft") || banner.contains("Windows") {
                ("SMB".to_string(), extract_version_from_banner(banner))
            } else {
                ("SMB".to_string(), None)
            }
        }
        1433 => {
            if banner.contains("Microsoft") || banner.contains("SQL Server") {
                ("MSSQL".to_string(), extract_version_from_banner(banner))
            } else {
                ("MSSQL".to_string(), None)
            }
        }
        1434 => {
            if banner.contains("Microsoft") || banner.contains("SQL Server") {
                (
                    "MSSQL Monitor".to_string(),
                    extract_version_from_banner(banner),
                )
            } else {
                ("MSSQL Monitor".to_string(), None)
            }
        }
        1521 => {
            if banner.contains("Oracle") {
                ("Oracle".to_string(), extract_version_from_banner(banner))
            } else {
                ("Oracle".to_string(), None)
            }
        }
        3306 => {
            if banner.contains("MySQL") {
                ("MySQL".to_string(), extract_version_from_banner(banner))
            } else if banner.contains("MariaDB") {
                ("MariaDB".to_string(), extract_version_from_banner(banner))
            } else {
                ("MySQL".to_string(), None)
            }
        }
        3389 => {
            if banner.contains("Remote Desktop") || banner.contains("Terminal Services") {
                ("RDP".to_string(), None)
            } else {
                ("RDP".to_string(), None)
            }
        }
        5432 => {
            if banner.contains("PostgreSQL") {
                (
                    "PostgreSQL".to_string(),
                    extract_version_from_banner(banner),
                )
            } else {
                ("PostgreSQL".to_string(), None)
            }
        }
        5900 | 5901 => {
            if banner.contains("RFB") {
                ("VNC".to_string(), extract_version_from_banner(banner))
            } else {
                ("VNC".to_string(), None)
            }
        }
        6379 => {
            if banner.contains("Redis") {
                let version = extract_version_from_banner(banner);
                if version.is_none() && banner.lines().count() > 1 {
                    let lines: Vec<&str> = banner.lines().collect();
                    if lines.len() > 1 {
                        return ("Redis".to_string(), extract_version_from_banner(lines[1]));
                    }
                }
                ("Redis".to_string(), version)
            } else {
                ("Redis".to_string(), None)
            }
        }
        27017 => {
            if banner.contains("MongoDB") {
                ("MongoDB".to_string(), extract_version_from_banner(banner))
            } else {
                ("MongoDB".to_string(), None)
            }
        }
        11211 => {
            if banner.contains("memcached") {
                ("Memcached".to_string(), extract_version_from_banner(banner))
            } else {
                ("Memcached".to_string(), None)
            }
        }
        _ => {
            if banner_lower.contains("ssh") {
                ("SSH".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("http") || banner.contains("HTTP") {
                ("HTTP".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("ftp") {
                ("FTP".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("smtp") || banner_lower.contains("mail") {
                ("SMTP".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("dns") {
                ("DNS".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("mysql") {
                ("MySQL".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("postgres") {
                (
                    "PostgreSQL".to_string(),
                    extract_version_from_banner(banner),
                )
            } else if banner_lower.contains("mongodb") {
                ("MongoDB".to_string(), extract_version_from_banner(banner))
            } else if banner_lower.contains("redis") {
                ("Redis".to_string(), extract_version_from_banner(banner))
            } else {
                ("Unknown".to_string(), None)
            }
        }
    };

    (service, version)
}

fn extract_version_from_banner(banner: &str) -> Option<String> {
    if banner.is_empty() {
        return None;
    }

    let patterns = [
        r"[\d]+\.[\d]+\.[\d]+",
        r"[\d]+\.[\d]+",
        r"version[\s_-]*[\d]+\.[\d]+",
        r"v[\d]+\.[\d]+",
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(mat) = re.find(banner) {
                return Some(mat.as_str().to_string());
            }
        }
    }

    None
}

fn check_vulnerability(service: &str, version: &Option<String>) -> Option<String> {
    let version_str = version.as_ref()?;

    let vuln_patterns: Vec<(&str, Vec<&str>)> = vec![
        (
            "SSH",
            vec![
                "OpenSSH_5",
                "OpenSSH_6",
                "OpenSSH_7.0",
                "OpenSSH_7.1",
                "OpenSSH_7.2",
            ],
        ),
        (
            "HTTP",
            vec![
                "Apache/2.2",
                "Apache/2.0",
                "nginx/1.0",
                "nginx/1.1",
                "nginx/1.2",
                "nginx/1.3",
                "nginx/1.4",
                "nginx/1.5",
                "nginx/1.6",
            ],
        ),
        ("MySQL", vec!["5.0", "5.1", "5.5"]),
        ("MariaDB", vec!["5.0", "5.1", "5.5"]),
        ("PostgreSQL", vec!["9.0", "9.1", "9.2", "9.3", "9.4"]),
        ("MongoDB", vec!["1.", "2.0", "2.2", "2.4", "2.6"]),
        (
            "Redis",
            vec!["1.", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.8"],
        ),
        ("RDP", vec![]),
        ("SMB", vec![]),
    ];

    for &(service_name, ref patterns) in &vuln_patterns {
        if service.eq_ignore_ascii_case(service_name) {
            for pattern in patterns {
                if version_str.contains(pattern) {
                    return Some(format!(
                        "Potentially vulnerable {} version detected",
                        service
                    ));
                }
            }
        }
    }

    None
}

fn get_service_solution(service: &str, port: u16) -> Option<String> {
    let solution = match service {
        "SSH" => Some("Restrict SSH access to specific IP ranges using firewalls; use key-based authentication; disable password authentication; change default port if possible".to_string()),
        "Telnet" => Some("Disable Telnet immediately; use SSH instead for secure remote access".to_string()),
        "SMTP" => Some("Configure SMTP to require authentication for relay; implement SPF, DKIM, DMARC; restrict access to mail servers".to_string()),
        "DNS" => Some("Restrict DNS zone transfers to authorized servers; implement response rate limiting; use DNSSEC".to_string()),
        "MSRPC" => Some("Block MSRPC ports at firewall; keep Windows systems patched".to_string()),
        "NetBIOS" => Some("Disable NetBIOS over TCP/IP; block ports 137-139 at firewall".to_string()),
        "SMB" => Some("Disable SMBv1; patch regularly; restrict access to file shares; use SMB signing".to_string()),
        "MSSQL" => Some("Use strong sa password; apply principle of least privilege; enable network encryption; patch regularly".to_string()),
        "Oracle" => Some("Change default passwords; apply CPU patches regularly; use database firewalls".to_string()),
        "MySQL" | "MariaDB" => Some("Use strong root password; bind to localhost if possible; remove anonymous users; update regularly".to_string()),
        "PostgreSQL" => Some("Use strong passwords; modify pg_hba.conf to restrict connections; enable SSL; keep updated".to_string()),
        "RDP" => Some("Enable Network Level Authentication; use strong passwords; limit users who can RDP; consider VPN gateway".to_string()),
        "VNC" => Some("Use strong passwords; tunnel VNC over SSH; consider disabling if not needed".to_string()),
        "Redis" => Some("Require authentication; bind to localhost or internal network only; rename dangerous commands; use firewall rules".to_string()),
        "MongoDB" => Some("Enable authentication; bind to localhost; disable unnecessary interfaces; keep updated".to_string()),
        "Memcached" => Some("Bind to localhost or use firewall; enable SASL authentication if available".to_string()),
        "HTTP" => Some("Keep web server software updated; disable unnecessary modules; use WAF; implement HTTPS".to_string()),
        "FTP" => Some("Use SFTP or FTPS instead of plain FTP; implement strong authentication".to_string()),
        _ => None
    };

    if matches!(port, 22 | 23 | 3389 | 5900 | 5901) {
        Some(format!("{} Exposure Risk: This service provides remote administrative access and should never be exposed directly to the internet. Use VPN or jump host for remote management.", service))
    } else if matches!(port, 1433 | 1434 | 3306 | 5432 | 1521 | 27017 | 6379) {
        Some(format!("{} Exposure Risk: Database exposed to network - implement network segmentation, strong authentication, and encryption", service))
    } else {
        solution
    }
}

fn get_cvss_score(service: &str, _port: u16) -> Option<f32> {
    let base_score = match service {
        "SSH" | "RDP" | "VNC" => 9.0,
        "Telnet" => 9.5,
        "MSSQL" | "MySQL" | "MariaDB" | "PostgreSQL" | "Oracle" | "MongoDB" => 8.5,
        "Redis" | "Memcached" => 8.0,
        "SMB" => 7.5,
        "DNS" => 6.0,
        "SMTP" => 5.0,
        "HTTP" | "FTP" => 4.0,
        _ => 3.0,
    };

    Some(base_score)
}

pub async fn execute(
    _target_url: &str,
    target_host: &str,
    network_rules: &[NetworkRequestTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Vec<FindingOwned> {
    let mut all_findings = Vec::new();

    for net_rule in network_rules {
        let host_to_scan = net_rule.host.replace("{{Hostname}}", target_host);

        tracing::debug!(target = %host_to_scan, ports = ?net_rule.ports, protocol = %net_rule.protocol, "Starting network port scan");

        let mut findings = Vec::new();
        let mut critical_findings = Vec::new();

        struct ScanPortResult {
            port: u16,
            banner_text: String,
        }

        let protocol_lower = net_rule.protocol.to_lowercase();
        let run_tcp = protocol_lower.contains("tcp")
            || protocol_lower == "all"
            || protocol_lower == "both"
            || protocol_lower.is_empty();
        let run_udp =
            protocol_lower.contains("udp") || protocol_lower == "all" || protocol_lower == "both";

        // Parse ports using the new parser to support ranges
        let ports_str = net_rule.ports.join(",");
        let parsed_ports = match parse_port_ranges(&ports_str) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(target = %host_to_scan, error = %e, "Failed to parse ports");
                continue;
            }
        };
        // Convert u16 back to string for the network scan functions
        let ports_as_strings: Vec<String> = parsed_ports.iter().map(|p| p.to_string()).collect();

        let mut port_results: Vec<ScanPortResult> = Vec::new();

        if run_udp && run_tcp {
            // Concurrent execution
            let udp_future = udp::scan_ports(
                &host_to_scan,
                &ports_as_strings,
                net_rule.banner_timeout_ms,
                false,
            );

            let tcp_future = tcp::scan_ports(
                &host_to_scan,
                &ports_as_strings,
                net_rule.banner_timeout_ms,
                false,
                net_rule.send_probe.clone(),
                false, // stealth_syn_scan
            );

            let (udp_res, tcp_res) = tokio::join!(udp_future, tcp_future);

            port_results.extend(udp_res.unwrap_or_default().into_iter().map(|r| {
                ScanPortResult {
                    port: r.port,
                    banner_text: r
                        .response
                        .as_ref()
                        .map(|v| String::from_utf8_lossy(v).to_string())
                        .unwrap_or_default(),
                }
            }));

            port_results.extend(tcp_res.into_iter().map(|r| ScanPortResult {
                port: r.port,
                banner_text: r.banner.unwrap_or_default(),
            }));
        } else if run_udp {
            let results = udp::scan_ports(
                &host_to_scan,
                &ports_as_strings,
                net_rule.banner_timeout_ms,
                false,
            )
            .await;
            port_results.extend(results.unwrap_or_default().into_iter().map(|r| {
                ScanPortResult {
                    port: r.port,
                    banner_text: r
                        .response
                        .as_ref()
                        .map(|v| String::from_utf8_lossy(v).to_string())
                        .unwrap_or_default(),
                }
            }));
        } else if run_tcp {
            let results = tcp::scan_ports(
                &host_to_scan,
                &ports_as_strings,
                net_rule.banner_timeout_ms,
                false,
                net_rule.send_probe.clone(), // Pass send_probe here
                false,                       // stealth_syn_scan
            )
            .await;
            port_results.extend(results.into_iter().map(|r| ScanPortResult {
                port: r.port,
                banner_text: r.banner.unwrap_or_default(),
            }));
        }

        if port_results.is_empty() {
            continue;
        }

        for port_result in &port_results {
            let (service, version) =
                identify_service_from_banner(port_result.port, &port_result.banner_text);
            let vuln_check = check_vulnerability(&service, &version);
            let solution = get_service_solution(&service, port_result.port);
            let cvss_score = get_cvss_score(&service, port_result.port);

            let service_desc = match &version {
                Some(v) => format!("{} {}", service, v),
                None => service.clone(),
            };

            let is_critical = SENSITIVE_PORTS.contains(&port_result.port);
            let base_finding = format!("Port {} open - {}", port_result.port, service_desc);
            let mut finding_details = String::new();
            finding_details.push_str(&base_finding);
            if let Some(vuln) = &vuln_check {
                finding_details.push_str(format!(" -> {}", vuln).as_str());
            }

            let mut compliance = HashMap::new();
            compliance.insert("service".to_string(), service.clone());
            if let Some(v) = &version {
                compliance.insert("version".to_string(), v.clone());
            }
            if let Some(vuln) = &vuln_check {
                compliance.insert("vulnerability".to_string(), vuln.clone());
            }
            // Solution and CVSS are natively on ScanResult now, but keep in compliance too
            if let Some(sol) = &solution {
                compliance.insert("solution".to_string(), sol.clone());
            }
            if let Some(score) = &cvss_score {
                compliance.insert("cvss_score".to_string(), score.to_string());
            }

            if net_rule.matchers.is_empty() {
                let severity = template_meta.template_severity().to_string();
                let _adjusted_severity = if is_critical && !vuln_check.is_none() {
                    if severity == "Info" {
                        "Medium".to_string()
                    } else if severity == "Low" {
                        "High".to_string()
                    } else if severity == "Medium" {
                        "High".to_string()
                    } else {
                        severity
                    }
                } else if is_critical {
                    if severity == "Info" {
                        "Low".to_string()
                    } else if severity == "Low" {
                        "Medium".to_string()
                    } else {
                        severity
                    }
                } else {
                    severity
                };

                let result = FindingOwned::from_template_and_info(
                    template_id,
                    template_meta,
                    format!("{}:{}", host_to_scan, port_result.port),
                    finding_details,
                );
                if is_critical {
                    critical_findings.push(result);
                } else {
                    findings.push(result);
                }
            } else {
                let banner_text = &port_result.banner_text;
                let mut matched = false;
                'matcher_loop: for matcher in &net_rule.matchers {
                    if matcher.r#type == "regex" && matcher.part == "banner" {
                        for pattern in &matcher.regex {
                            let Ok(re) = Regex::new(pattern) else {
                                continue;
                            };
                            if re.is_match(banner_text.as_bytes()) {
                                matched = true;
                                tracing::debug!(port = %port_result.port, pattern = %pattern, "Vulnerability banner match found");
                                let mut payload = format!(
                                    "Port {} matched '{}' — {}",
                                    port_result.port,
                                    pattern,
                                    banner_text.trim()
                                );
                                if service != "Unknown" {
                                    payload.push_str(
                                        format!(
                                            ", Service: {} {}",
                                            service,
                                            version.as_deref().unwrap_or("")
                                        )
                                        .as_str(),
                                    );
                                }
                                compliance
                                    .insert("matched_pattern".to_string(), pattern.to_string());
                                break 'matcher_loop;
                            }
                        }
                    }
                }

                if matched {
                    let severity = template_meta.template_severity().to_string();
                    let _adjusted_severity = if is_critical && !vuln_check.is_none() {
                        if severity == "Info" {
                            "Medium".to_string()
                        } else if severity == "Low" {
                            "High".to_string()
                        } else if severity == "Medium" {
                            "High".to_string()
                        } else {
                            severity
                        }
                    } else if is_critical {
                        if severity == "Info" {
                            "Low".to_string()
                        } else if severity == "Low" {
                            "Medium".to_string()
                        } else {
                            severity
                        }
                    } else {
                        severity
                    };

                    let result = FindingOwned::from_template_and_info(
                        template_id,
                        template_meta,
                        format!("{}:{}", host_to_scan, port_result.port),
                        finding_details,
                    );
                    if is_critical {
                        critical_findings.push(result);
                    } else {
                        findings.push(result);
                    }
                }
            }
        }

        all_findings.extend(critical_findings);
        all_findings.extend(findings);
    }

    all_findings
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SENSITIVE_PORTS tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sensitive_ports_contains_known_services() {
        assert!(
            SENSITIVE_PORTS.contains(&22),
            "SSH port 22 should be sensitive"
        );
        assert!(
            SENSITIVE_PORTS.contains(&3306),
            "MySQL port 3306 should be sensitive"
        );
        assert!(
            SENSITIVE_PORTS.contains(&3389),
            "RDP port 3389 should be sensitive"
        );
        assert!(
            SENSITIVE_PORTS.contains(&6379),
            "Redis port 6379 should be sensitive"
        );
    }

    // -----------------------------------------------------------------------
    // identify_service_from_banner tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_identify_ssh_on_port_22() {
        let (service, _version) =
            identify_service_from_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3");
        assert_eq!(service, "SSH");
    }

    #[test]
    fn test_identify_ssh_on_port_22_without_ssh_in_banner() {
        let (service, _version) = identify_service_from_banner(22, "something else");
        assert_eq!(service, "Unknown");
    }

    #[test]
    fn test_identify_telnet_on_port_23() {
        let (service, _version) = identify_service_from_banner(23, "Telnet Server ready");
        assert_eq!(service, "Telnet");
    }

    #[test]
    fn test_identify_smtp_sendmail_on_port_25() {
        let (service, _version) = identify_service_from_banner(25, "220 Sendmail ready");
        assert_eq!(service, "Sendmail");
    }

    #[test]
    fn test_identify_smtp_postfix_on_port_25() {
        let (service, _version) =
            identify_service_from_banner(25, "220 Postfix ESMTP server ready");
        assert_eq!(service, "Postfix");
    }

    #[test]
    fn test_identify_dns_on_port_53() {
        let (service, version) = identify_service_from_banner(53, "named 9.16.1");
        assert_eq!(service, "DNS");
        assert!(version.is_some());
    }

    #[test]
    fn test_identify_smb_on_port_445() {
        let (service, _version) = identify_service_from_banner(445, "Samba 4.15.0");
        assert_eq!(service, "SMB");
    }

    #[test]
    fn test_identify_mysql_on_port_3306() {
        let (service, version) = identify_service_from_banner(3306, "MySQL 5.7.38-log");
        assert_eq!(service, "MySQL");
        assert!(version.is_some());
    }

    #[test]
    fn test_identify_mariadb_on_port_3306() {
        let (service, _version) = identify_service_from_banner(3306, "MariaDB 10.6.0");
        assert_eq!(service, "MariaDB");
    }

    #[test]
    fn test_identify_rdp_on_port_3389() {
        let (service, _version) = identify_service_from_banner(3389, "Remote Desktop Server");
        assert_eq!(service, "RDP");
    }

    #[test]
    fn test_identify_postgresql_on_port_5432() {
        let (service, version) = identify_service_from_banner(5432, "PostgreSQL 14.5");
        assert_eq!(service, "PostgreSQL");
        assert!(version.is_some());
    }

    #[test]
    fn test_identify_vnc_on_port_5900() {
        let (service, _version) = identify_service_from_banner(5900, "RFB 003.008");
        assert_eq!(service, "VNC");
    }

    #[test]
    fn test_identify_redis_on_port_6379() {
        let (service, version) = identify_service_from_banner(6379, "Redis 6.2.6");
        assert_eq!(service, "Redis");
        assert!(version.is_some());
    }

    #[test]
    fn test_identify_mongodb_on_port_27017() {
        let (service, _version) = identify_service_from_banner(27017, "MongoDB 5.0.0");
        assert_eq!(service, "MongoDB");
    }

    #[test]
    fn test_identify_unknown_port_guesses_from_banner() {
        let (service, _version) = identify_service_from_banner(9999, "FTP server ready");
        assert_eq!(service, "FTP");
    }

    #[test]
    fn test_identify_unknown_port_returns_unknown() {
        let (service, _version) = identify_service_from_banner(9999, "garbage data");
        assert_eq!(service, "Unknown");
    }

    #[test]
    fn test_identify_http_on_non_standard_port() {
        let (service, _version) = identify_service_from_banner(8080, "HTTP/1.1 200 OK");
        assert_eq!(service, "HTTP");
    }

    #[test]
    fn test_identify_ssh_on_non_standard_port() {
        let (service, _version) = identify_service_from_banner(2222, "SSH-2.0-OpenSSH");
        assert_eq!(service, "SSH");
    }

    // -----------------------------------------------------------------------
    // extract_version_from_banner tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_version_semver() {
        let ver = extract_version_from_banner("OpenSSH_8.9p1 Ubuntu-3");
        assert!(ver.is_some());
        assert!(ver.unwrap().contains("8.9"));
    }

    #[test]
    fn test_extract_version_major_minor() {
        let ver = extract_version_from_banner("Apache/2.4.51");
        assert!(ver.is_some());
    }

    #[test]
    fn test_extract_version_empty_returns_none() {
        assert!(extract_version_from_banner("").is_none());
    }

    #[test]
    fn test_extract_version_no_version_in_banner() {
        assert!(extract_version_from_banner("Hello World").is_none());
    }

    #[test]
    fn test_extract_version_version_prefix() {
        let ver = extract_version_from_banner("v1.2.3");
        assert!(ver.is_some());
    }

    // -----------------------------------------------------------------------
    // check_vulnerability tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_vulnerability_vulnerable_ssh() {
        let result = check_vulnerability("SSH", &Some("OpenSSH_7.0".to_string()));
        assert!(result.is_some());
        assert!(result.unwrap().contains("vulnerable"));
    }

    #[test]
    fn test_check_vulnerability_patched_ssh() {
        let result = check_vulnerability("SSH", &Some("OpenSSH_9.0".to_string()));
        assert!(result.is_none());
    }

    #[test]
    fn test_check_vulnerability_no_version() {
        let result = check_vulnerability("SSH", &None);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_vulnerability_vulnerable_apache() {
        let result = check_vulnerability("HTTP", &Some("Apache/2.2".to_string()));
        assert!(result.is_some());
    }

    #[test]
    fn test_check_vulnerability_vulnerable_mysql() {
        let result = check_vulnerability("MySQL", &Some("MySQL 5.1".to_string()));
        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // get_cvss_score tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cvss_score_ssh() {
        assert_eq!(get_cvss_score("SSH", 22), Some(9.0));
    }

    #[test]
    fn test_cvss_score_telnet() {
        assert_eq!(get_cvss_score("Telnet", 23), Some(9.5));
    }

    #[test]
    fn test_cvss_score_http() {
        assert_eq!(get_cvss_score("HTTP", 80), Some(4.0));
    }

    // -----------------------------------------------------------------------
    // get_service_solution tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_solution_for_ssh_mentions_exposure_risk() {
        let sol = get_service_solution("SSH", 22).unwrap();
        assert!(sol.contains("Exposure Risk"));
        assert!(sol.contains("remote administrative access"));
    }

    #[test]
    fn test_solution_for_mysql_mentions_network_segmentation() {
        let sol = get_service_solution("MySQL", 3306).unwrap();
        assert!(sol.contains("Database exposed"));
    }

    #[test]
    fn test_solution_for_unknown_service() {
        let sol = get_service_solution("Unknown", 9999);
        assert!(sol.is_none());
    }

    #[test]
    fn test_solution_for_redis() {
        let sol = get_service_solution("Redis", 6379).unwrap();
        assert!(sol.contains("authentication"));
        assert!(sol.contains("Database exposed"));
    }
}
