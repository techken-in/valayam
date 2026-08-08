use rand::seq::SliceRandom;
use rand::Rng;

/// User-Agent rotator for browser impersonation
pub struct UserAgentRotator {}

impl UserAgentRotator {
    /// Create a new UserAgentRotator
    pub fn new() -> Result<Self, String> {
        Ok(Self {})
    }

    /// Create a new UserAgentRotator with default user agents
    pub fn with_defaults() -> Self {
        Self {}
    }

    /// Generate the next realistic User-Agent using a statistical probability approach
    pub fn next_ua(&self) -> String {
        // Fast, thread-local RNG for high concurrent throughput
        let mut rng = rand::thread_rng();

        // 1. Choose OS Platform (Windows 60%, Mac 25%, Linux 5%, Mobile 10%)
        let platform_roll = rng.gen_range(0..100);
        let platform = if platform_roll < 60 {
            "Windows NT 10.0; Win64; x64"
        } else if platform_roll < 85 {
            let mac_versions = ["14_5", "14_4_1", "14_4", "13_6", "12_7"];
            let version = mac_versions
                .choose(&mut rng)
                .expect("mac_versions is non-empty");
            return format!("Mozilla/5.0 (Macintosh; Intel Mac OS X {}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36", version, rng.gen_range(120..=128));
        } else if platform_roll < 90 {
            "X11; Linux x86_64"
        } else {
            let ios_versions = ["17_5_1", "17_4", "16_7"];
            let version = ios_versions
                .choose(&mut rng)
                .expect("ios_versions is non-empty");
            return format!("Mozilla/5.0 (iPhone; CPU iPhone OS {} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", version);
        };

        // 2. Choose Browser Engine for Desktop (Chrome 65%, Edge 20%, Firefox 15%)
        let browser_roll = rng.gen_range(0..100);
        if browser_roll < 65 {
            // Chrome
            let chrome_major = rng.gen_range(120..=128);
            format!("Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36", platform, chrome_major)
        } else if browser_roll < 85 {
            // Edge
            let edge_major = rng.gen_range(120..=128);
            format!("Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36 Edg/{}.0.0.0", platform, edge_major, edge_major)
        } else {
            // Firefox
            let ff_major = rng.gen_range(120..=130);
            let gecko_version = format!("{}.0", ff_major);
            let mut platform_str = platform.to_string();
            // Firefox uses different platform strings than WebKit for Windows
            if platform_str == "Windows NT 10.0; Win64; x64" {
                platform_str = format!("Windows NT 10.0; Win64; x64; rv:{}", gecko_version);
            }
            format!(
                "Mozilla/5.0 ({}) Gecko/20100101 Firefox/{}",
                platform_str, gecko_version
            )
        }
    }
}
