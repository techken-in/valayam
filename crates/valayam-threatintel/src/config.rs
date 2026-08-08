#[derive(Clone, Debug)]
pub struct CoreConfig {
    pub cisa_kev_url: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl CoreConfig {
    pub fn from_env() -> Self {
        Self {
            cisa_kev_url: std::env::var("CISA_KEV_URL").unwrap_or_else(|_| "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".to_string()),
        }
    }
}
