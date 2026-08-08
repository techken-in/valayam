use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use url::Url;

use crate::parsers::{javascript, openapi, wasm};
use crate::wordlists::CRAWLER_PROBE_PATHS;
use valayam_engine::rate_limiter::RateLimiter;
use valayam_network::network::http::StealthHttpClient;

pub struct Crawler {
    client: Arc<StealthHttpClient>,
    target_host: String,
    target_url: Url,
    visited: Arc<Mutex<HashSet<String>>>,
    discovered_urls: Arc<Mutex<HashSet<String>>>,
    max_depth: usize,
    rate_limiter: Option<Arc<RateLimiter>>,
    crawl_headers: Option<HashMap<String, String>>,
}

impl Crawler {
    pub fn new(
        client: Arc<StealthHttpClient>,
        target_url_str: &str,
        max_depth: usize,
        rate_limiter: Option<Arc<RateLimiter>>,
        crawl_headers: Option<HashMap<String, String>>,
    ) -> Result<Self, String> {
        let target_url = Url::parse(target_url_str).map_err(|e| e.to_string())?;
        let target_host = target_url
            .host_str()
            .ok_or_else(|| "Target URL has no host".to_string())?
            .to_string();

        Ok(Self {
            client,
            target_host,
            target_url,
            visited: Arc::new(Mutex::new(HashSet::new())),
            discovered_urls: Arc::new(Mutex::new(HashSet::new())),
            max_depth,
            rate_limiter,
            crawl_headers,
        })
    }
}

fn extract_links_from_html(body_text: &str) -> HashSet<String> {
    let mut found = HashSet::new();
    let document = scraper::Html::parse_document(body_text);
    let selector = scraper::Selector::parse("a[href], form[action], script[src], link[href]")
        .expect("static css selector");
    for el in document.select(&selector) {
        let link = el
            .value()
            .attr("href")
            .or(el.value().attr("action"))
            .or(el.value().attr("src"))
            .unwrap_or("");
        if !link.is_empty() {
            found.insert(link.to_string());
        }
    }
    found
}

impl Crawler {
    pub async fn run(self) -> HashSet<String> {
        let mut join_set = JoinSet::new();

        {
            let mut vis = self.visited.lock().await;
            vis.insert(self.target_url.to_string());
        }

        let probe_clone = self.clone_instance();
        join_set.spawn(async move { probe_clone.probe_wordlists().await });

        let self_clone = self.clone_instance();
        let target_url = self.target_url.clone();
        join_set.spawn(async move { self_clone.crawl_url_inner(target_url, 0).await });

        let concurrency_semaphore = Arc::new(tokio::sync::Semaphore::new(10));

        while let Some(res) = join_set.join_next().await {
            if let Ok(discovered) = res {
                for (new_url, new_depth) in discovered {
                    let mut vis = self.visited.lock().await;
                    let url_str = new_url.to_string();
                    if !vis.contains(&url_str) && new_depth <= self.max_depth {
                        vis.insert(url_str.clone());
                        let worker_clone = self.clone_instance();
                        let sem_clone = concurrency_semaphore.clone();

                        join_set.spawn(async move {
                            let _permit = sem_clone.acquire().await;
                            worker_clone.crawl_url_inner(new_url, new_depth).await
                        });
                    }
                }
            }
        }

        let result = self.discovered_urls.lock().await;
        result.clone()
    }

    async fn probe_wordlists(&self) -> Vec<(Url, usize)> {
        let mut newly_discovered = Vec::new();

        for &path in CRAWLER_PROBE_PATHS {
            if let Ok(probe_url) = self.target_url.join(path) {
                let probe_url_str = probe_url.to_string();

                if let Some(ref rl) = self.rate_limiter {
                    rl.acquire().await;
                }

                if let Ok(resp) = self
                    .client
                    .send_request(
                        "GET",
                        &probe_url_str,
                        self.crawl_headers.as_ref(),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    if resp.status().is_success() {
                        {
                            let mut disc = self.discovered_urls.lock().await;
                            disc.insert(probe_url_str.clone());
                        }

                        if probe_url_str.ends_with(".json") || probe_url_str.contains("api-docs") {
                            if let Ok(body_text) = resp.text().await {
                                let api_endpoints = openapi::extract_openapi_endpoints(&body_text);
                                for endpoint in api_endpoints {
                                    if let Ok(full_api_url) = self.target_url.join(&endpoint) {
                                        let api_url_str = full_api_url.to_string();
                                        let mut disc = self.discovered_urls.lock().await;
                                        disc.insert(api_url_str.clone());
                                        newly_discovered.push((full_api_url, 0));
                                    }
                                }
                            }
                        }
                    }
                }

                let mut vis = self.visited.lock().await;
                vis.insert(probe_url_str);
            }
        }

        newly_discovered
    }

    async fn crawl_url_inner(&self, url: Url, depth: usize) -> Vec<(Url, usize)> {
        let url_str = url.to_string();

        {
            let mut disc = self.discovered_urls.lock().await;
            disc.insert(url_str.clone());
        }

        if let Some(ref rl) = self.rate_limiter {
            rl.acquire().await;
        }

        tracing::debug!(url = %url_str, depth = depth, "Crawling page");

        let response = match self
            .client
            .send_request(
                "GET",
                &url_str,
                self.crawl_headers.as_ref(),
                None,
                None,
                None,
            )
            .await
        {
            Ok(resp) => resp,
            Err(_) => return vec![],
        };

        if !response.status().is_success() {
            return vec![];
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let mut next_urls = Vec::new();

        if content_type.contains("javascript")
            || content_type.contains("typescript")
            || url_str.ends_with(".js")
        {
            if let Ok(body_text) = response.text().await {
                let js_endpoints = javascript::extract_js_endpoints(&body_text);
                next_urls.extend(self.process_discovered_routes(js_endpoints, depth));

                let js_params = javascript::extract_js_parameters(&body_text);
                if !js_params.is_empty() {
                    tracing::info!(url = %url_str, "Discovered {} parameters in JS bundle: {:?}", js_params.len(), js_params);
                }
            }
        } else if url_str.ends_with(".wasm") || content_type.contains("wasm") {
            if let Ok(bytes) = response.bytes().await {
                let wasm_endpoints = wasm::extract_wasm_endpoints(&bytes);
                next_urls.extend(self.process_discovered_routes(wasm_endpoints, depth));
            }
        } else if content_type.contains("html") {
            if let Ok(body_text) = response.text().await {
                let found_links = extract_links_from_html(&body_text);
                next_urls.extend(self.process_discovered_routes(found_links, depth));
            }
        }

        next_urls
    }

    fn process_discovered_routes(
        &self,
        routes: HashSet<String>,
        depth: usize,
    ) -> Vec<(Url, usize)> {
        let mut valid_routes = Vec::new();
        for route in routes {
            let normalized_url = if route.starts_with("http://") || route.starts_with("https://") {
                match Url::parse(&route) {
                    Ok(u) => u,
                    Err(_) => continue,
                }
            } else if route.starts_with("//") {
                match Url::parse(&format!("https:{}", route)) {
                    Ok(u) => u,
                    Err(_) => continue,
                }
            } else {
                match self.target_url.join(&route) {
                    Ok(u) => u,
                    Err(_) => continue,
                }
            };

            if let Some(host) = normalized_url.host_str() {
                if host == self.target_host {
                    valid_routes.push((normalized_url, depth + 1));
                }
            }
        }
        valid_routes
    }

    fn clone_instance(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
            target_host: self.target_host.clone(),
            target_url: self.target_url.clone(),
            visited: Arc::clone(&self.visited),
            discovered_urls: Arc::clone(&self.discovered_urls),
            max_depth: self.max_depth,
            rate_limiter: self.rate_limiter.clone(),
            crawl_headers: self.crawl_headers.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn test_crawler_new_with_headers() {
        let client = Arc::new(StealthHttpClient::new(false, false, None, false).unwrap());
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer secret".to_string());

        let crawler = Crawler::new(
            client,
            "https://example.com/api",
            2,
            None,
            Some(headers.clone()),
        )
        .unwrap();

        assert_eq!(crawler.crawl_headers.unwrap(), headers);
        assert_eq!(crawler.target_host, "example.com");
    }
}
