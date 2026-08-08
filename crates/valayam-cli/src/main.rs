#[tokio::main]
async fn main() -> anyhow::Result<()> {
    valayam_cli::run_cli().await
}
