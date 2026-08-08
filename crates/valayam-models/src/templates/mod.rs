//! Template definitions for all vulnerability scan types.
//!
//! Each submodule defines the section schema and default templates for a
//! specific scan category: web application, network, cloud, mobile, IoT,
//! API, graphql, etc. The `schema` module defines the core VulnerabilityTemplate.

pub mod auth_logic;
pub mod auto_exploit;
pub mod auto_redteam;
pub mod aws_escalate;
pub mod azure_gcp_escalate;
pub mod browser_audit;
pub mod cicd_audit;
pub mod client_secret_audit;
pub mod cloud_sec;
pub mod container_audit;
pub mod cors_audit;
pub mod cred_monitor;
pub mod csp_audit;
pub mod ct_log_audit;
pub mod deep_analysis;
pub mod dependency_audit;
pub mod dns_audit;
pub mod dom_redirect_audit;
pub mod drift_detect;
pub mod easm;
pub mod extractors;
pub mod functions;
pub mod fuzzer;
pub mod graphql_audit;
pub mod grpc_audit;
pub mod header_scorecard;
pub mod helpers;
pub mod http_scan;
pub mod iac_audit;
pub mod idp_audit;
pub mod implant_deploy;
pub mod iot_audit;
pub mod k8s_audit;
pub mod matcher;
pub mod mitre_mapping;
pub mod mobile_audit;
pub mod network_scan;
pub mod nuclei_compat;
pub mod oauth_audit;
pub mod pii_leak_audit;
pub mod port_scan;
pub mod remediation_gen;
pub mod reputation_audit;
pub mod sast_secrets;
pub mod sast_taint;
pub mod sbom_audit;
pub mod scada_audit;
pub mod schema;
pub mod schema_drift;
pub mod scripting;
pub mod section;
pub mod serverless_audit;
pub mod subdomain_takeover;
pub mod tls_audit;
pub mod ui_proxy;
pub mod waf_bypass_verify;
pub mod web3_audit;
