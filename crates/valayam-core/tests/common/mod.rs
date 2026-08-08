//! Module: common
//!
//! Automatically added module documentation.

#![allow(dead_code)]
use std::sync::Arc;
use valayam_core::network::http::StealthHttpClient;
use valayam_engine::traits::FindingOwned;

/// Starts a mockito server returning "pong" on GET /ping.
pub fn mock_server() -> (mockito::ServerGuard, String) {
    let mut s = mockito::Server::new();
    let url = s.url();
    s.mock("GET", "/ping")
        .with_status(200)
        .with_header("content-type", "text/plain")
        .with_body("pong")
        .create();
    (s, url)
}

/// A valid YAML VulnerabilityTemplate that requests GET /ping and matches on "pong".
pub fn sample_template() -> String {
    r#"
id: integ-ping-test
info:
  name: Ping Test
  severity: info
requests:
  - method: GET
    path: /ping
    matchers:
      - type: word
        part: body
        words:
          - pong
      - type: status
        part: status
        status:
          - 200
"#
    .to_string()
}

/// Pre-populated FindingOwned for reporter tests.
pub fn sample_finding() -> FindingOwned {
    FindingOwned {
        scan_id: uuid::Uuid::default(),
        template_id: "report-001".into(),
        template_name: "Reporter Test".into(),
        severity: "critical".into(),
        target: "https://example.com".into(),
        matched_at: "/admin".into(),
        description: Some("vulnerability found".into()),
        solution: Some("apply fix".into()),
        extracted_data: None,
        metadata: Default::default(),
    }
}

/// Builds a StealthHttpClient with default options, wrapped in Arc.
pub fn build_http_client() -> Arc<StealthHttpClient> {
    Arc::new(StealthHttpClient::new(false, false, None, false).unwrap())
}
