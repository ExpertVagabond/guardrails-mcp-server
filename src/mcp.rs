use crate::engine::GuardrailsEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

pub async fn run_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Arc::new(Mutex::new(GuardrailsEngine::new(Default::default())));
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid JSON-RPC: {e}");
                continue;
            }
        };

        let response = handle_request(&req, &engine).await;

        if let Some(resp) = response {
            let mut out = stdout.lock();
            serde_json::to_writer(&mut out, &resp)?;
            out.write_all(b"\n")?;
            out.flush()?;
        }
    }

    Ok(())
}

async fn handle_request(
    req: &JsonRpcRequest,
    engine: &Arc<Mutex<GuardrailsEngine>>,
) -> Option<JsonRpcResponse> {
    let id = req.id.clone().unwrap_or(Value::Null);

    match req.method.as_str() {
        "initialize" => Some(JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "guardrails-mcp-server",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        }),

        "notifications/initialized" => None,

        "tools/list" => Some(JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!({ "tools": tool_definitions() })),
            error: None,
        }),

        "tools/call" => {
            let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
            let result = call_tool(name, args, engine).await;
            Some(JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: Some(result),
                error: None,
            })
        }

        _ => Some(JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(json!({
                "code": -32601,
                "message": format!("method not found: {}", req.method)
            })),
        }),
    }
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "validate_input",
            "description": "Validate and sanitize input text for prompt injection, malicious code, and PII",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Text to validate" },
                    "user_id": { "type": "string", "description": "Optional user ID for rate limiting" }
                },
                "required": ["text"]
            }
        },
        {
            "name": "filter_output",
            "description": "Filter output text to redact sensitive data (PII, secrets, credentials)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Text to filter" }
                },
                "required": ["text"]
            }
        },
        {
            "name": "check_policy",
            "description": "Evaluate text against security policies",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Text to evaluate" },
                    "policy_names": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Specific policies to check (omit for all)"
                    }
                },
                "required": ["text"]
            }
        },
        {
            "name": "get_audit_logs",
            "description": "Retrieve audit logs with optional filtering",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "event_type": { "type": "string", "description": "Filter by event type" },
                    "limit": { "type": "integer", "description": "Max entries to return (default 50)" }
                }
            }
        },
        {
            "name": "get_stats",
            "description": "Get current engine statistics — active users, request counts, blocked requests",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "update_config",
            "description": "Update guardrails engine configuration",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "max_requests_per_minute": { "type": "integer" },
                    "max_tokens_per_request": { "type": "integer" },
                    "enable_input_validation": { "type": "boolean" },
                    "enable_output_filtering": { "type": "boolean" },
                    "enable_policy_enforcement": { "type": "boolean" },
                    "enable_rate_limiting": { "type": "boolean" }
                }
            }
        },
        {
            "name": "add_policy",
            "description": "Add a custom security policy",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Policy name" },
                    "pattern": { "type": "string", "description": "Regex pattern to match" },
                    "action": { "type": "string", "enum": ["block", "warn", "redact"], "description": "Action on match" },
                    "description": { "type": "string", "description": "Policy description" }
                },
                "required": ["name", "pattern", "action"]
            }
        },
        {
            "name": "remove_policy",
            "description": "Remove a custom security policy by name",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Policy name to remove" }
                },
                "required": ["name"]
            }
        }
    ])
}

async fn call_tool(name: &str, args: Value, engine: &Arc<Mutex<GuardrailsEngine>>) -> Value {
    let mut eng = engine.lock().await;

    match name {
        "validate_input" => {
            let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let user_id = args.get("user_id").and_then(|v| v.as_str()).unwrap_or("anonymous");
            let result = eng.process_input(text, user_id);
            json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap() }] })
        }

        "filter_output" => {
            let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let result = eng.filter_output(text);
            json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap() }] })
        }

        "check_policy" => {
            let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let policies: Option<Vec<String>> = args.get("policy_names")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let result = eng.check_policy(text, policies.as_deref());
            json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap() }] })
        }

        "get_audit_logs" => {
            let event_type = args.get("event_type").and_then(|v| v.as_str());
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let logs = eng.get_audit_logs(event_type, limit);
            json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&logs).unwrap() }] })
        }

        "get_stats" => {
            let stats = eng.get_stats();
            json!({ "content": [{ "type": "text", "text": serde_json::to_string_pretty(&stats).unwrap() }] })
        }

        "update_config" => {
            if let Some(v) = args.get("max_requests_per_minute").and_then(|v| v.as_u64()) {
                eng.config.max_requests_per_minute = v as usize;
            }
            if let Some(v) = args.get("max_tokens_per_request").and_then(|v| v.as_u64()) {
                eng.config.max_tokens_per_request = v as usize;
            }
            if let Some(v) = args.get("enable_input_validation").and_then(|v| v.as_bool()) {
                eng.config.enable_input_validation = v;
            }
            if let Some(v) = args.get("enable_output_filtering").and_then(|v| v.as_bool()) {
                eng.config.enable_output_filtering = v;
            }
            if let Some(v) = args.get("enable_policy_enforcement").and_then(|v| v.as_bool()) {
                eng.config.enable_policy_enforcement = v;
            }
            if let Some(v) = args.get("enable_rate_limiting").and_then(|v| v.as_bool()) {
                eng.config.enable_rate_limiting = v;
            }
            json!({ "content": [{ "type": "text", "text": "Configuration updated" }] })
        }

        "add_policy" => {
            let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let pattern = args.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("block");
            let desc = args.get("description").and_then(|v| v.as_str()).unwrap_or("");
            match eng.add_policy(name, pattern, action, desc) {
                Ok(()) => json!({ "content": [{ "type": "text", "text": format!("Policy '{name}' added") }] }),
                Err(e) => json!({ "content": [{ "type": "text", "text": format!("Error: {e}") }], "isError": true }),
            }
        }

        "remove_policy" => {
            let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if eng.remove_policy(name) {
                json!({ "content": [{ "type": "text", "text": format!("Policy '{name}' removed") }] })
            } else {
                json!({ "content": [{ "type": "text", "text": format!("Policy '{name}' not found") }], "isError": true })
            }
        }

        _ => json!({
            "content": [{ "type": "text", "text": format!("Unknown tool: {name}") }],
            "isError": true
        }),
    }
}
