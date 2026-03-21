mod audit;
mod engine;
mod filter;
mod mcp;
mod policy;
mod validator;

use tracing_subscriber::EnvFilter;

// ── Security: constants & validation ──────────────────────────────────

/// Maximum input length in bytes for any single request payload.
pub const MAX_INPUT_BYTES: usize = 512_000;

/// Maximum number of policies that can be loaded simultaneously.
pub const MAX_POLICIES: usize = 1_000;

/// Maximum audit log entries retained in memory.
pub const MAX_AUDIT_ENTRIES: usize = 50_000;

/// Maximum number of concurrent validation requests.
pub const MAX_CONCURRENT_REQUESTS: usize = 100;

/// Sanitize error messages to prevent information leakage.
pub fn sanitize_error(err: &dyn std::fmt::Display) -> String {
    let msg = err.to_string();
    let mut sanitized = msg.clone();
    // Strip file paths
    let path_re = regex::Regex::new(r"/[^\s]+/").unwrap_or_else(|_| regex::Regex::new(r"^$").unwrap());
    sanitized = path_re.replace_all(&sanitized, "[path]/").to_string();
    // Truncate
    if sanitized.len() > 300 {
        sanitized.truncate(300);
        sanitized.push_str("...");
    }
    sanitized
}

/// Validate that input does not exceed the maximum allowed size.
pub fn validate_input_size(input: &str) -> Result<(), String> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "Input size {} exceeds maximum allowed {} bytes",
            input.len(),
            MAX_INPUT_BYTES
        ));
    }
    Ok(())
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
