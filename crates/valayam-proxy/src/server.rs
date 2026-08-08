use crate::state::{ProxyRequestData, ProxyState};
use axum::{
    extract::State,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize)]
pub struct StatusResponse {
    status: String,
    active_proxies: usize,
}

#[derive(Serialize, Deserialize)]
pub struct ModificationRequest {
    pub request_id: String,
    pub modified_body: Option<String>,
    pub modified_headers: Option<Vec<(String, String)>>,
}

pub struct UiProxyServer;

impl UiProxyServer {
    pub async fn start(port: u16, state: ProxyState) -> Result<(), String> {
        let app = Router::new()
            .route("/", get(Self::dashboard_handler))
            .route("/api/status", get(Self::status_handler))
            .route("/api/pending", get(Self::pending_handler))
            .route("/api/modify", post(Self::modify_handler))
            .with_state(state);

        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| e.to_string())?;

        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("UI Proxy Server error: {}", e);
            }
        });

        Ok(())
    }

    async fn dashboard_handler() -> Html<&'static str> {
        Html(include_str!("index.html"))
    }

    async fn status_handler(State(state): State<ProxyState>) -> Json<StatusResponse> {
        Json(StatusResponse {
            status: "running".to_string(),
            active_proxies: state.pending_requests.len(),
        })
    }

    async fn pending_handler(State(state): State<ProxyState>) -> Json<Vec<ProxyRequestData>> {
        let mut pending = Vec::new();
        for entry in state.pending_requests.iter() {
            pending.push(entry.value().request_data.clone());
        }
        Json(pending)
    }

    async fn modify_handler(
        State(state): State<ProxyState>,
        Json(payload): Json<ModificationRequest>,
    ) -> Json<serde_json::Value> {
        if let Some((_, intercepted)) = state.pending_requests.remove(&payload.request_id) {
            let mut req_data = intercepted.request_data;
            if let Some(body) = payload.modified_body {
                req_data.body = body;
            }
            if let Some(headers) = payload.modified_headers {
                req_data.headers = headers;
            }
            let _ = intercepted.tx.send(Some(req_data));
            Json(serde_json::json!({
                "status": "success",
                "message": format!("Request {} modified and forwarded.", payload.request_id)
            }))
        } else {
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Request {} not found.", payload.request_id)
            }))
        }
    }
}
