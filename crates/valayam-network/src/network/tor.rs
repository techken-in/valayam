use reqwest::Proxy;

/// Configures Tor proxy routing for stealth scanning.
pub struct TorRouter;

impl TorRouter {
    /// Returns a configured reqwest Proxy pointing to a local Tor SOCKS5 listener.
    pub fn get_proxy(tor_port: u16) -> Result<Proxy, String> {
        let proxy_url = format!("socks5h://127.0.0.1:{}", tor_port);
        Proxy::all(&proxy_url).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_proxy_default_socks5_port() {
        let _proxy = TorRouter::get_proxy(9050).expect("should create proxy for default Tor port");
    }

    #[test]
    fn test_get_proxy_custom_port() {
        let _proxy =
            TorRouter::get_proxy(9150).expect("should create proxy for Tor Browser Bundle port");
    }

    #[test]
    fn test_get_proxy_all_common_ports() {
        for port in [9050u16, 9150u16] {
            let _proxy = TorRouter::get_proxy(port).expect("standard tor ports should work");
        }
    }
}
