use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::oneshot;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct ProxyRequestData {
    pub id: String,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[non_exhaustive]
pub struct InterceptedRequest {
    pub request_data: ProxyRequestData,
    pub tx: oneshot::Sender<Option<ProxyRequestData>>,
}

impl InterceptedRequest {
    /// Create a new InterceptedRequest.
    pub fn new(request_data: ProxyRequestData, tx: oneshot::Sender<Option<ProxyRequestData>>) -> Self {
        Self { request_data, tx }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub struct ProxyState {
    pub pending_requests: Arc<DashMap<String, InterceptedRequest>>,
}

impl ProxyState {
    /// Create a new ProxyState.
    pub fn new() -> Self {
        Self {
            pending_requests: Arc::new(DashMap::new()),
        }
    }
}

impl Default for ProxyState {
    fn default() -> Self {
        Self::new()
    }
}
