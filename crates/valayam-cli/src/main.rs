#[tokio::main]
async fn main() {
    if let Err(e) = valayam_cli::run_cli().await {
        use colored::Colorize;
        eprintln!("{} {}", "[-] Error:".red().bold(), e);
        std::process::exit(1);
    }
}
