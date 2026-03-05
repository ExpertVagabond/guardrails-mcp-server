# guardrails-mcp-server

[\![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[\![MCP](https://img.shields.io/badge/MCP-Compatible-blue.svg)](https://modelcontextprotocol.io)
[\![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org)

MCP server for AI agent security guardrails. Provides input validation, prompt injection detection, PII redaction, output filtering, policy enforcement, rate limiting, and comprehensive audit logging.

## Tools

| Tool | Description |
|------|-------------|
| `validate_input` | Validate and sanitize incoming requests through all guardrail checks |
| `filter_output` | Filter and redact sensitive data (PII, secrets, credentials) from responses |
| `check_policy` | Evaluate a request against security policies (RBAC, resource access, quotas) |
| `get_audit_logs` | Query the audit log with filtering by type, user, time range |
| `get_stats` | Get engine statistics including active users, block rate, request counts |
| `update_config` | Update guardrail configuration at runtime |

## Security Features

- **Prompt Injection Detection** -- 12 regex patterns for jailbreak, DAN mode, system prompt override
- **PII Detection and Redaction** -- SSN, credit card, email, phone, IP, API keys, AWS keys, JWT, passwords, private keys, connection strings
- **Malicious Code Blocking** -- eval, exec, subprocess, child_process, shell injection
- **Policy Engine** -- Block sensitive paths, dangerous tools, unauthenticated destructive ops, URL allowlist, maintenance windows
- **Rate Limiting** -- Per-user sliding window (configurable requests/minute)
- **Audit Logging** -- Timestamped events with metrics, log rotation, external handler support

## Install

```bash
npm install
```

## Configuration

```json
{
  "mcpServers": {
    "guardrails": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/guardrails-mcp-server/index.js"]
    }
  }
}
```

## Project Structure

```
src/engine/GuardrailsEngine.js    # Core orchestration
src/validators/InputValidator.js   # Prompt injection and PII detection
src/filters/OutputFilter.js        # Redaction and harmful content blocking
src/policies/PolicyEngine.js       # RBAC, quotas, maintenance windows
src/audit/AuditLogger.js           # Event logging and metrics
```

## License

[MIT](LICENSE)
