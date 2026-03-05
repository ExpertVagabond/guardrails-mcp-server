mod engine;
mod validator;
mod filter;
mod policy;
mod audit;
mod mcp;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("guardrails-mcp-server starting");

    if let Err(e) = mcp::run_stdio().await {
        tracing::error!("server error: {e}");
        std::process::exit(1);
    }
}
