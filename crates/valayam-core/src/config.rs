/// Core configuration parameters for the valayam agent/engine.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CoreConfig {
    /// Documentation for this item.
    pub valayam_registry_user: Option<String>,
    /// Documentation for this item.
    pub valayam_registry_pass: Option<String>,
    /// The URL to fetch CISA KEV data from.
    pub cisa_kev_url: String,
}

impl CoreConfig {
    /// Create a new CoreConfig with all required fields.
    pub fn new(
        valayam_registry_user: Option<String>,
        valayam_registry_pass: Option<String>,
        cisa_kev_url: String,
    ) -> Self {
        Self {
            valayam_registry_user,
            valayam_registry_pass,
            cisa_kev_url,
        }
    }
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl CoreConfig {
    /// Documentation for this item.
    pub fn from_env() -> Self {
        Self {
            valayam_registry_user: std::env::var("VALAYAM_REGISTRY_USER").ok(),
            valayam_registry_pass: std::env::var("VALAYAM_REGISTRY_PASS").ok(),
            cisa_kev_url: std::env::var("CISA_KEV_URL").unwrap_or_else(|_| "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".to_string()),
        }
    }
}
