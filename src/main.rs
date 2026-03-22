mod audit;
mod engine;
mod filter;
mod mcp;
mod policy;
mod validator;

use tracing_subscriber::EnvFilter;

// Re-export shared constants from psm-mcp-core for backwards compatibility.
pub use psm_mcp_core::input::MAX_INPUT_BYTES;

/// Maximum number of policies that can be loaded simultaneously.
pub const MAX_POLICIES: usize = 1_000;

/// Maximum audit log entries retained in memory.
pub use psm_mcp_core::audit::MAX_AUDIT_ENTRIES;

/// Maximum number of concurrent validation requests.
pub const MAX_CONCURRENT_REQUESTS: usize = 100;

/// Sanitize error messages to prevent information leakage.
/// Delegates to psm-mcp-core's sanitize_error.
pub fn sanitize_error(err: &dyn std::fmt::Display) -> String {
    psm_mcp_core::error::sanitize_error(&err.to_string(), 300)
}

/// Validate that input does not exceed the maximum allowed size.
/// Delegates to psm-mcp-core's validate_input_size.
pub fn validate_input_size(input: &str) -> Result<(), String> {
    psm_mcp_core::input::validate_input_size(input, MAX_INPUT_BYTES)
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    tracing::info!(
        "guardrails-mcp-server starting (max_input={}B, max_policies={}, max_audit={})",
        MAX_INPUT_BYTES,
        MAX_POLICIES,
        MAX_AUDIT_ENTRIES,
    );

    if let Err(e) = mcp::run_stdio().await {
        tracing::error!("server error: {}", sanitize_error(&e));
        std::process::exit(1);
    }
}
