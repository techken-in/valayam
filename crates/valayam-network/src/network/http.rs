use crate::network::ssrf_filter::{reject_private_ip, SsrfConfig};
use crate::network_metrics;
use crate::stealth::proxy::ProxyRotator;
use crate::stealth::tls::{Ja3Ja4Profile, Ja3Ja4Spoofer};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};
use valayam_models::error::ScannerError;

/// A pool of reqwest clients, each configured with a different proxy.
/// Clients are created lazily and reused.
struct ProxiedClientPool {
    /// Proxy rotator for cycling through proxies
    rotator: Arc<ProxyRotator>,
    /// Pre-built reqwest clients per proxy address
    clients: Mutex<HashMap<String, Client>>,
    /// Next proxy to use (round-robin)
    current_proxy: Mutex<Option<String>>,
    timeout: u32,
    default_headers: Option<reqwest::header::HeaderMap>,
}

impl ProxiedClientPool {
    fn new(
        rotator: ProxyRotator,
        timeout: u32,
        default_headers: Option<reqwest::header::HeaderMap>,
    ) -> Self {
        Self {
            rotator: Arc::new(rotator),
            clients: Mutex::new(HashMap::new()),
            current_proxy: Mutex::new(None),
            timeout,
            default_headers,
        }
    }

    /// Get a reqwest client for the next proxy in rotation.
    async fn next_client(&self) -> Option<(Client, String)> {
        let proxy_address = self.rotator.next().await?;

        // Check if we already have a client for this proxy
        {
            let clients = self.clients.lock().await;
            if let Some(client) = clients.get(&proxy_address) {
                let mut current = self.current_proxy.lock().await;
                *current = Some(proxy_address.clone());
                return Some((client.clone(), proxy_address));
            }
        }

        // Build a new client with this proxy
        let proxy = match reqwest::Proxy::all(&proxy_address) {
            Ok(p) => p,
            Err(e) => {
                warn!(proxy = %proxy_address, error = %e, "Failed to create proxy configuration");
                return None;
            }
        };

        let mut client_builder = Client::builder()
            .proxy(proxy)
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(self.timeout as u64));

        // Construct and attach the TLS config if we're simulating spoofing.
        // NOTE: In the ProxiedClientPool we aren't passing the profile down currently,
        // so we use the default permissive config. In a full implementation, the profile
        // would be passed into the pool.
        let tls_config = crate::stealth::tls::TlsConfig::new_with_spoofing(None)
            .ok()
            .and_then(|c| c.build().ok());
        if let Some(cfg) = tls_config {
            client_builder = client_builder.use_preconfigured_tls(cfg);
        }

        if let Some(ref hdrs) = self.default_headers {
            client_builder = client_builder.default_headers(hdrs.clone());
        }

        let client = match client_builder.build() {
            Ok(c) => c,
            Err(e) => {
                warn!(proxy = %proxy_address, error = %e, "Failed to build proxied client");
                return None;
            }
        };

        // Cache the client
        {
            let mut clients = self.clients.lock().await;
            if clients.len() >= 1000 {
                // Random/pseudo-LRU eviction: remove one arbitrary entry to prevent memory spike
                let key_to_remove = clients.keys().next().cloned();
                if let Some(k) = key_to_remove {
                    clients.remove(&k);
                }
            }
            clients.insert(proxy_address.clone(), client.clone());
        }
        {
            let mut current = self.current_proxy.lock().await;
            *current = Some(proxy_address.clone());
        }

        Some((client, proxy_address))
    }

    /// Report a success for the current proxy.
    async fn record_success(&self) {
        let current = self.current_proxy.lock().await;
        if let Some(ref addr) = *current {
            self.rotator.record_success(addr).await;
        }
    }

    /// Report a failure for the current proxy.
    async fn record_failure(&self) {
        let current = self.current_proxy.lock().await;
        if let Some(ref addr) = *current {
            self.rotator.record_failure(addr).await;
        }
    }
}

/// Enhanced HTTP client with WAF evasion capabilities.
#[derive(Clone)]
pub struct StealthHttpClient {
    /// Base reqwest client (without proxy)
    client: Client,
    /// Pool of proxy-backed clients for IP rotation
    proxy_client_pool: Option<Arc<ProxiedClientPool>>,
    /// Proxy rotator for IP rotation metadata
    #[allow(dead_code)]
    proxy_rotator: Option<Arc<ProxyRotator>>,
    /// User-Agent rotator for browser impersonation
    user_agent_rotator: Option<Arc<valayam_common::user_agent::UserAgentRotator>>,
    /// JA3/JA4 spoofer for TLS fingerprint evasion
    #[allow(dead_code)]
    ja3_ja4_spoofer: Option<Ja3Ja4Spoofer>,
    /// Whether to follow meta-refresh redirects
    follow_meta_refresh: bool,
    /// Global circuit breaker
    circuit_breaker: Arc<crate::network::resilience::CircuitBreaker>,
    /// Global adaptive rate limiter
    adaptive_rate_limiter: Arc<crate::network::resilience::AdaptiveRateLimiter>,
    /// SSRF protection configuration
    ssrf_config: SsrfConfig,
}

impl StealthHttpClient {
    pub fn new(
        use_proxy_rotation: bool,
        use_user_agent_rotation: bool,
        ja3_ja4_profile: Option<Ja3Ja4Profile>,
        follow_meta_refresh: bool,
    ) -> Result<Self, ScannerError> {
        Self::new_with_options(
            use_proxy_rotation,
            use_user_agent_rotation,
            ja3_ja4_profile,
            follow_meta_refresh,
            None,
            None,
            None,
            None,
        )
    }

    /// Create a new StealthHttpClient with stealth features and advanced options.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_options(
        use_proxy_rotation: bool,
        use_user_agent_rotation: bool,
        ja3_ja4_profile: Option<Ja3Ja4Profile>,
        follow_meta_refresh: bool,
        timeout_opt: Option<u32>,
        default_headers: Option<HashMap<String, String>>,
        cb_config: Option<(u32, u64)>, // (max_failures, timeout_ms)
        ssrf_config: Option<SsrfConfig>,
    ) -> Result<Self, ScannerError> {
        let timeout = timeout_opt.unwrap_or(30);

        // Convert HashMap to HeaderMap
        let mut headers_map = None;
        if let Some(hdrs) = default_headers {
            let mut hm = reqwest::header::HeaderMap::new();
            for (k, v) in hdrs {
                if let (Ok(key), Ok(value)) = (
                    reqwest::header::HeaderName::try_from(&k),
                    reqwest::header::HeaderValue::from_str(&v),
                ) {
                    hm.insert(key, value);
                }
            }
            headers_map = Some(hm);
        }

        // Build base client
        let mut client_builder = Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(timeout as u64));

        if let Some(ref hm) = headers_map {
            client_builder = client_builder.default_headers(hm.clone());
        }

        // Add proxy rotation if enabled
        let (proxy_client_pool, proxy_rotator) = if use_proxy_rotation {
            let rotator = ProxyRotator::new();
            let pool = ProxiedClientPool::new(rotator.clone(), timeout, headers_map);
            (Some(Arc::new(pool)), Some(Arc::new(rotator)))
        } else {
            (None, None)
        };

        // Add user-agent rotation if enabled
        let user_agent_rotator = if use_user_agent_rotation {
            Some(Arc::new(
                valayam_common::user_agent::UserAgentRotator::new().map_err(|e| {
                    valayam_models::error::ScannerError::NetworkError(tokio::io::Error::other(e))
                })?,
            ))
        } else {
            None
        };

        // Add JA3/JA4 spoofing if profile specified
        let tls_cfg = crate::stealth::tls::TlsConfig::new_with_spoofing(ja3_ja4_profile)?;
        let rustls_client_config = tls_cfg.build()?;
        client_builder = client_builder.use_preconfigured_tls(rustls_client_config);

        let ja3_ja4_spoofer = ja3_ja4_profile.map(Ja3Ja4Spoofer::new);

        let client = client_builder.build()?;

        let cb_max_fails = cb_config.map(|c| c.0 as usize).unwrap_or(50);
        let cb_timeout = cb_config.map(|c| c.1).unwrap_or(30000);

        Ok(Self {
            client,
            proxy_client_pool,
            proxy_rotator,
            user_agent_rotator,
            ja3_ja4_spoofer,
            follow_meta_refresh,
            circuit_breaker: Arc::new(crate::network::resilience::CircuitBreaker::new(
                cb_max_fails,
                cb_timeout,
            )),
            adaptive_rate_limiter: Arc::new(crate::network::resilience::AdaptiveRateLimiter::new(
                0, 0, 5000, 50,
            )),
            ssrf_config: ssrf_config.unwrap_or_default(),
        })
    }

    /// Send an HTTP request with stealth enhancements.
    pub async fn send_request(
        &self,
        method: &str,
        url: &str,
        headers: Option<&HashMap<String, String>>,
        body: Option<&str>,
        follow_redirects: Option<bool>,
        timeout_override: Option<Duration>,
    ) -> Result<reqwest::Response, ScannerError> {
        let start = Instant::now();

        if self.circuit_breaker.is_open() {
            return Err(ScannerError::CircuitBreakerOpen);
        }

        // SSRF protection — blocks private/internal IPs unless --allow-internal
        reject_private_ip(url, &self.ssrf_config)?;

        self.adaptive_rate_limiter.wait().await;

        let http_method: reqwest::Method = method
            .parse()
            .map_err(|_| ScannerError::InvalidHttpMethod(method.to_string()))?;

        let should_follow = follow_redirects.unwrap_or(false);
        let max_redirects = if should_follow { 5 } else { 0 };
        let max_retries = 3;
        let mut current_url = url.to_string();
        let mut redirect_count = 0;
        let mut retry_count = 0;
        let mut final_response = None;

        while redirect_count <= max_redirects {
            let mut proxied_used = false;
            let mut response_result = None;

            // If proxy rotation is configured, use a proxied client from the pool.
            if let Some(ref pool) = self.proxy_client_pool {
                if let Some((proxied_client, proxy_addr)) = pool.next_client().await {
                    proxied_used = true;
                    debug!(proxy = %proxy_addr, "Using proxied client for request");
                    let mut proxied_req = proxied_client.request(http_method.clone(), &current_url);
                    // Apply headers
                    if let Some(hdrs) = headers {
                        for (key, value) in hdrs {
                            proxied_req = proxied_req.header(key, value);
                        }
                    }
                    // Apply body
                    if let Some(b) = body {
                        proxied_req = proxied_req.body(b.to_string());
                    }
                    // Apply timeout
                    if let Some(t) = timeout_override {
                        proxied_req = proxied_req.timeout(t);
                    }
                    // Apply user-agent rotation
                    if let Some(ref rotator) = self.user_agent_rotator {
                        let ua = rotator.next_ua();
                        proxied_req = proxied_req.header(reqwest::header::USER_AGENT, ua);
                    }
                    response_result = Some(
                        send_with_proxied_req(proxied_req, pool, self.follow_meta_refresh).await,
                    );
                } else {
                    warn!("No healthy proxies available, falling back to direct connection");
                }
            }

            if !proxied_used {
                // Build the request on the base (direct) client
                let mut request_builder = self.client.request(http_method.clone(), &current_url);

                // Apply headers if provided
                if let Some(hdrs) = headers {
                    for (key, value) in hdrs {
                        request_builder = request_builder.header(key, value);
                    }
                }

                // Apply body if provided
                if let Some(b) = body {
                    request_builder = request_builder.body(b.to_string());
                }

                // Apply timeout
                if let Some(t) = timeout_override {
                    request_builder = request_builder.timeout(t);
                }

                // Apply user-agent rotation if configured
                if let Some(ref rotator) = self.user_agent_rotator {
                    let user_agent = rotator.next_ua();
                    request_builder =
                        request_builder.header(reqwest::header::USER_AGENT, user_agent);
                }

                // Send the request
                response_result = Some(
                    request_builder
                        .send()
                        .await
                        .map_err(ScannerError::HttpClientError),
                );
            }

            let response_res = if let Some(res) = response_result {
                res
            } else {
                return Err(ScannerError::TooManyRedirects); // Fallback error if request wasn't sent
            };

            match &response_res {
                Ok(resp) => {
                    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        self.adaptive_rate_limiter.handle_too_many_requests();
                        self.circuit_breaker.record_failure();
                    } else if resp.status().is_server_error() {
                        self.circuit_breaker.record_failure();
                    } else {
                        self.adaptive_rate_limiter.handle_success();
                        self.circuit_breaker.record_success();
                    }
                }
                Err(_) => {
                    self.circuit_breaker.record_failure();
                }
            }

            let response = match response_res {
                Ok(r) => r,
                Err(e) => {
                    retry_count += 1;
                    if retry_count <= max_retries {
                        let delay = 500 * (1 << retry_count);
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        continue;
                    }
                    return Err(e);
                }
            };
            let elapsed = start.elapsed().as_secs_f64();
            network_metrics::record_http_request(
                method,
                response.status().as_u16(),
                proxied_used,
                elapsed,
            );

            // Handle meta-refresh redirects if enabled
            let response = if self.follow_meta_refresh {
                handle_meta_refresh(response, &self.client).await?
            } else {
                response
            };

            if should_follow && response.status().is_redirection() {
                if let Some(location) = response.headers().get(reqwest::header::LOCATION) {
                    if let Ok(loc_str) = location.to_str() {
                        if let Ok(parsed_url) = reqwest::Url::parse(&current_url) {
                            if let Ok(next_url) = parsed_url.join(loc_str) {
                                current_url = next_url.to_string();
                                redirect_count += 1;
                                continue;
                            }
                        }
                    }
                }
            }

            final_response = Some(response);
            break;
        }

        if let Some(resp) = final_response {
            Ok(resp)
        } else {
            Err(ScannerError::TooManyRedirects)
        }
    }

    /// Get the underlying reqwest client for advanced usage.
    pub fn client(&self) -> &Client {
        &self.client
    }
}

/// Send a request via a proxied client with success/failure tracking.
/// Meta-refresh following is not supported in proxy mode (the proxied client's redirect
/// policy handles it instead).
async fn send_with_proxied_req(
    request_builder: reqwest::RequestBuilder,
    pool: &ProxiedClientPool,
    _follow_meta_refresh: bool,
) -> Result<reqwest::Response, ScannerError> {
    match request_builder.send().await {
        Ok(response) => {
            pool.record_success().await;
            if response.status().is_server_error() {
                pool.record_failure().await;
            }
            // Meta-refresh following in proxy mode would require the base client,
            // which would bypass the proxy — skip for proxy mode.
            Ok(response)
        }
        Err(e) => {
            pool.record_failure().await;
            Err(ScannerError::HttpClientError(e))
        }
    }
}

/// Handle meta-refresh redirects by checking the response body.
/// Returns the body text and an optional redirect URL.
async fn handle_meta_refresh(
    response: reqwest::Response,
    client: &Client,
) -> Result<reqwest::Response, ScannerError> {
    // Check content-type header first (cheap check before consuming body)
    let should_check = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_lowercase().contains("text/html"))
        .unwrap_or(false);

    if !should_check {
        return Ok(response);
    }

    if let Some(len) = response.content_length() {
        if len > 5 * 1024 * 1024 {
            // 5 MB limit
            return Ok(response);
        }
    }

    // Limit body read to 5MB to prevent chunked response DOS
    let mut bytes = Vec::new();
    let max_bytes = 5 * 1024 * 1024;

    // We can't use `response.bytes_stream()` since `stream` feature might not be enabled.
    // However `response.chunk()` allows reading chunks one by one.
    let mut current_response = response;
    while let Some(chunk) = current_response
        .chunk()
        .await
        .map_err(ScannerError::HttpClientError)?
    {
        if bytes.len() + chunk.len() > max_bytes {
            return Err(ScannerError::ResourceExhausted(
                "Meta-refresh body too large".to_string(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }

    let body = String::from_utf8_lossy(&bytes).to_string();

    if let Some(redirect_url) = extract_meta_refresh(&body) {
        debug!("Following meta-refresh redirect to: {}", redirect_url);
        // Issue a fresh GET for the redirect URL
        let redirect_resp = client
            .get(&redirect_url)
            .send()
            .await
            .map_err(ScannerError::from)?;
        return Ok(redirect_resp);
    }

    // Body was consumed but no redirect — return it as a new response
    Ok(build_text_response(body))
}

/// Build a minimal HTTP response from a string body.
fn build_text_response(body: String) -> reqwest::Response {
    // reqwest::Response implements From<http::Response<Body>>
    let http_response = http::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .body(body)
        .expect("Valid HTTP response");
    reqwest::Response::from(http_response)
}

use std::sync::OnceLock;
static META_REFRESH_RE1: OnceLock<regex::Regex> = OnceLock::new();
static META_REFRESH_RE2: OnceLock<regex::Regex> = OnceLock::new();

/// Extract redirect URL from meta-refresh tag in HTML.
fn extract_meta_refresh(html: &str) -> Option<String> {
    let re1 = META_REFRESH_RE1.get_or_init(|| regex::Regex::new(
        r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+\s*;\s*url\s*=\s*["']([^"']*)["'][^>]*>"#
    ).unwrap());

    let re2 = META_REFRESH_RE2.get_or_init(|| regex::Regex::new(
        r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["']\d+\s*;\s*url\s*=\s*([^"'\s>]+)"#
    ).unwrap());

    if let Some(cap) = re1.captures(html) {
        return Some(cap.get(1)?.as_str().to_string());
    }
    if let Some(cap) = re2.captures(html) {
        return Some(cap.get(1)?.as_str().to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stealth_http_client_creation() {
        let client = StealthHttpClient::new(true, true, Some(Ja3Ja4Profile::Chrome), true)
            .expect("Should create client");
        assert!(client
            .client()
            .get("https://example.com")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .is_ok());
    }

    #[tokio::test]
    async fn test_extract_meta_refresh() {
        let html = r#"<html><head><meta http-equiv="refresh" content="5;url=https://example.com/"></head><body></body></html>"#;
        let result = extract_meta_refresh(html);
        assert_eq!(result, Some("https://example.com/".to_string()));

        let html_no_meta = r#"<html><head><title>No redirect</title></head><body></body></html>"#;
        let result = extract_meta_refresh(html_no_meta);
        assert_eq!(result, None);
    }
}
