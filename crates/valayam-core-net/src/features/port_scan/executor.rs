use valayam_models::finding::FindingOwned;
use valayam_models::templates::port_scan::PortScanTemplate;
use valayam_models::TemplateMetadata;
use valayam_network::network::tcp;

/// Define commonly exposed administrative/dangerous services that should not be publicly accessible
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

/// Extract version string from banner using common patterns
fn extract_version_from_banner(banner: &str) -> Option<String> {
    if banner.is_empty() {
        return None;
    }

    // Common version patterns
    let patterns = [
        r"[\d]+\.[\d]+\.[\d]+",        // X.Y.Z
        r"[\d]+\.[\d]+",               // X.Y
        r"version[\s_-]*[\d]+\.[\d]+", // version X.Y
        r"v[\d]+\.[\d]+",              // vX.Y
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

/// Identify service and version from banner
fn identify_service_from_banner(port: u16, banner: &str) -> (String, Option<String>) {
    let banner_lower = banner.to_lowercase();

    // Determine service based on port and banner content
    let (service, version) = match port {
        22 => {
            // SSH banner usually looks like: "SSH-2.0-OpenSSH_7.4"
            if banner_lower.contains("ssh") {
                let version = extract_version_from_banner(banner);
                ("SSH".to_string(), version)
            } else {
                ("Unknown".to_string(), None)
            }
        }
        23 => {
            // Telnet banners vary widely
            if banner_lower.contains("telnet") {
                ("Telnet".to_string(), None)
            } else {
                ("Unknown".to_string(), None)
            }
        }
        25 => {
            // SMTP banners often contain server info
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
            // DNS doesn't usually give banners on TCP, but if it does...
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
            if banner.contains("Samba")
                || banner.contains("Microsoft")
                || banner.contains("Windows")
            {
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
        3389 => ("RDP".to_string(), None),
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
                // VNC protocol identifier
                ("VNC".to_string(), extract_version_from_banner(banner))
            } else {
                ("VNC".to_string(), None)
            }
        }
        6379 => {
            if banner.contains("Redis") {
                let version = extract_version_from_banner(banner);
                // Redis often sends just "Redis" followed by version on newline
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
            // Generic detection based on banner content
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

/// Check if service version appears to be potentially vulnerable
fn check_vulnerability(service: &str, version: &Option<String>) -> Option<String> {
    let version_str = version.as_ref()?;

    // Define version patterns that might indicate vulnerable versions
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
        ("RDP", vec![]), // RDP version checking is complex, skip for now
        ("SMB", vec![]), // SMB version checking via banner is limited
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

pub async fn execute(
    target_host: &str,
    templates: &[PortScanTemplate],
    template_id: &str,
    template_meta: &dyn TemplateMetadata,
) -> Option<FindingOwned> {
    for template in templates {
        let host_to_scan = template
            .target
            .as_deref()
            .unwrap_or("{{Hostname}}")
            .replace("{{Hostname}}", target_host);

        // Filter to only scan sensitive ports if specific ports weren't provided
        let ports_to_scan = if template.ports.is_empty() {
            // Use our predefined sensitive ports
            SENSITIVE_PORTS
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<String>>()
        } else {
            // Use the ports specified in the template (convert u16 to String)
            template
                .ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<String>>()
        };

        tracing::debug!(target = %host_to_scan, ports = ?ports_to_scan,
                       "Starting sensitive port scan for administrative services");

        // Perform TCP connect scan with banner grabbing
        let port_results = tcp::scan_ports(
            &host_to_scan,
            &ports_to_scan,
            Some(2000), // 2 second timeout for banner grabbing
            true,       // Enable service detection
            None,       // send_probe
            false,      // stealth_syn_scan
        )
        .await;

        if port_results.is_empty() {
            // No sensitive ports found open
            continue;
        }

        // Process each open port for service identification and vulnerability checking
        let mut findings = Vec::new();
        let mut critical_findings = Vec::new();

        for port_result in &port_results {
            let (service, version) = identify_service_from_banner(
                port_result.port,
                port_result.banner.as_deref().unwrap_or(""),
            );

            // Check for potential vulnerabilities
            let vuln_check = check_vulnerability(&service, &version);

            // Build service description
            let service_desc = match &version {
                Some(v) => format!("{} {}", service, v),
                None => service.clone(),
            };

            // Create basic finding
            let finding = format!("Port {} open - {}", port_result.port, service_desc);

            // Check if this is a particularly sensitive service
            let is_critical = matches!(
                port_result.port,
                22 | 23 | 135 | 139 | 445 | 1433 | 1434 | 3389 | 27017 | 6379 | 11211
            );

            if is_critical {
                critical_findings.push(finding.clone());
                if let Some(vuln) = vuln_check {
                    critical_findings.push(format!("{} -> {}", finding, vuln));
                }
            } else {
                findings.push(finding.clone());
                if let Some(vuln) = vuln_check {
                    findings.push(format!("{} -> {}", finding, vuln));
                }
            }
        }

        // Return critical findings first, then others
        let mut all_findings = Vec::new();
        all_findings.extend(critical_findings);
        all_findings.extend(findings);

        if !all_findings.is_empty() {
            return Some(FindingOwned::from_template_and_info(
                template_id,
                template_meta,
                host_to_scan,
                format!("Sensitive services detected: {}", all_findings.join("; ")),
            ));
        }
    }

    None
}
