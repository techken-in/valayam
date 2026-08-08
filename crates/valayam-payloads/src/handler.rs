use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Handler for catching remote shells.
pub struct ShellHandler;

impl ShellHandler {
    /// Starts a reverse shell listener on a specific port.
    pub async fn start_reverse_listener(port: u16) -> Result<(), String> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| e.to_string())?;

        tracing::info!("Reverse shell listener started on {}", addr);

        tokio::spawn(async move {
            if let Ok((mut socket, peer_addr)) = listener.accept().await {
                tracing::warn!("Caught shell from {}!", peer_addr);
                let _ = socket
                    .write_all(b"Connected to Valayam Shell Handler\n")
                    .await;
            }
        });

        Ok(())
    }
}
