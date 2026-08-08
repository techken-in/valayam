use dashmap::DashSet;

/// Matches extracted indicators against known threat feeds concurrently.
#[derive(Default)]
pub struct IocMatcher {
    pub malicious_ips: DashSet<String>,
    pub malicious_domains: DashSet<String>,
}

impl IocMatcher {
    pub fn new() -> Self {
        Self {
            malicious_ips: DashSet::new(),
            malicious_domains: DashSet::new(),
        }
    }

    /// Checks if an IP is in the malicious IPs list.
    pub fn is_malicious_ip(&self, ip: &str) -> bool {
        self.malicious_ips.contains(ip)
    }

    /// Checks if a domain is in the malicious domains list.
    pub fn is_malicious_domain(&self, domain: &str) -> bool {
        self.malicious_domains.contains(domain)
    }

    /// Add an IP to the malicious list.
    pub fn add_malicious_ip(&self, ip: String) {
        self.malicious_ips.insert(ip);
    }

    /// Add a domain to the malicious list.
    pub fn add_malicious_domain(&self, domain: String) {
        self.malicious_domains.insert(domain);
    }
}
