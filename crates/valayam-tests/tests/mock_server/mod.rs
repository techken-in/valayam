use axum::{routing::get, Router};

use tokio::net::TcpListener;

pub async fn start_mock_server() -> String {
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/aws", get(|| async { "AKIAIOSFODNN7EXAMPLE" })) // Mock AWS key exposure
        .route("/db", get(|| async { "DB_PASSWORD=supersecret" })) // Mock DB password
        .route("/jwt", get(|| async { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" })); // Mock JWT

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://127.0.0.1:{}", port)
}
