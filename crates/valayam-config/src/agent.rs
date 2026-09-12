//! Agent configuration and wire protocol types.

use serde::{Deserialize, Serialize};

/// Agent configuration — defines how this worker connects to the platform.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AgentConfig {
    pub platform_url: String,
    pub worker_id: String,
    pub poll_interval_secs: u64,
    pub heartbeat_interval_secs: u64,
    pub capabilities: Vec<String>,
    pub job_secret: String,
}

impl AgentConfig {
    /// Create a new AgentConfig.
    pub fn new(
        platform_url: impl Into<String>,
        worker_id: impl Into<String>,
        poll_interval_secs: u64,
        heartbeat_interval_secs: u64,
        capabilities: Vec<String>,
        job_secret: impl Into<String>,
    ) -> Self {
        Self {
            platform_url: platform_url.into(),
            worker_id: worker_id.into(),
            poll_interval_secs,
            heartbeat_interval_secs,
            capabilities,
            job_secret: job_secret.into(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            platform_url: "http://localhost:8000".into(),
            worker_id: uuid::Uuid::new_v4().to_string(),
            poll_interval_secs: 5,
            heartbeat_interval_secs: 15,
            capabilities: vec!["wasm".into(), "grpc".into(), "native".into()],
            job_secret: String::new(),
        }
    }
}

/// Job dispatched by the platform for the worker to execute.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[non_exhaustive]
pub struct AgentJob {
    pub job_id: String,
    pub target_url: String,
    pub templates: Vec<AgentJobTemplate>,
    pub config: AgentJobConfig,
    pub auth: Option<AgentJobAuth>,
}

/// Job template.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[non_exhaustive]
pub struct AgentJobTemplate {
    pub id: String,
    pub yaml: String,
}

/// Job configuration.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[non_exhaustive]
pub struct AgentJobConfig {
    pub concurrency: Option<usize>,
    pub rate_limit: Option<u32>,
    pub timeout_secs: Option<u64>,
    pub crawl: Option<bool>,
    pub crawl_depth: Option<usize>,
    pub random_agent: Option<bool>,
    pub output_format: Option<String>,
}

/// Job authentication.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[non_exhaustive]
pub struct AgentJobAuth {
    pub job_token: String,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

/// Result payload posted back to the platform.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AgentJobResult {
    pub job_id: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: String,
    pub worker_id: String,
    pub metrics: serde_json::Value,
    pub findings: Vec<serde_json::Value>,
    pub errors: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_token: Option<String>,
}

impl AgentJobResult {
    /// Create a new AgentJobResult.
    pub fn new(
        job_id: impl Into<String>,
        status: impl Into<String>,
        started_at: impl Into<String>,
        completed_at: impl Into<String>,
        worker_id: impl Into<String>,
        metrics: serde_json::Value,
        findings: Vec<serde_json::Value>,
        errors: Vec<serde_json::Value>,
        job_token: Option<String>,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            status: status.into(),
            started_at: started_at.into(),
            completed_at: completed_at.into(),
            worker_id: worker_id.into(),
            metrics,
            findings,
            errors,
            job_token,
        }
    }
}

/// Heartbeat payload pushed to the platform every N seconds.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AgentHeartbeat {
    pub worker_id: String,
    pub version: String,
    pub status: String,
    pub current_job_id: Option<String>,
    pub cpu_usage_pct: f32,
    pub memory_usage_pct: f32,
    pub uptime_secs: u64,
    pub plugins_loaded: u32,
    pub templates_cached: u32,
}

impl AgentHeartbeat {
    /// Create a new AgentHeartbeat.
    pub fn new(
        worker_id: impl Into<String>,
        version: impl Into<String>,
        status: impl Into<String>,
        current_job_id: Option<String>,
        cpu_usage_pct: f32,
        memory_usage_pct: f32,
        uptime_secs: u64,
        plugins_loaded: u32,
        templates_cached: u32,
    ) -> Self {
        Self {
            worker_id: worker_id.into(),
            version: version.into(),
            status: status.into(),
            current_job_id,
            cpu_usage_pct,
            memory_usage_pct,
            uptime_secs,
            plugins_loaded,
            templates_cached,
        }
    }
}

/// Response from `POST /jobs/poll` — either a job or a `no-content` signal.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct PollResponse {
    pub job: Option<AgentJob>,
}

/// Poll error response
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct PollError {
    pub error: String,
}
