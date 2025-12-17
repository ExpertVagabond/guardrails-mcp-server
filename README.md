# AI Guardrails MCP Server

MCP server providing security guardrails for Claude Code and AI agents. Implements input validation, output filtering, policy enforcement, and audit logging.

## Features

- **Input Validation** - Sanitize and validate all inputs before processing
- **Output Filtering** - Redact sensitive data from responses
- **Policy Enforcement** - Enforce custom security policies
- **Audit Logging** - Complete audit trail of all requests
- **Rate Limiting** - Protect against abuse and overuse

## Architecture

```
User Request
     │
     ▼
┌─────────────────────────────────────┐
│       Guardrails Engine             │
├─────────────────────────────────────┤
│  ┌─────────┐  ┌──────────────────┐  │
│  │  Rate   │  │     Input        │  │
│  │ Limiter │──▶   Validator      │  │
│  └─────────┘  └────────┬─────────┘  │
│                        │            │
│               ┌────────▼─────────┐  │
│               │     Policy       │  │
│               │     Engine       │  │
│               └────────┬─────────┘  │
│                        │            │
│               ┌────────▼─────────┐  │
│               │     Output       │  │
│               │     Filter       │  │
│               └────────┬─────────┘  │
│                        │            │
│  ┌─────────────────────▼─────────┐  │
│  │        Audit Logger           │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
     │
     ▼
  Response
```

## Components

### GuardrailsEngine (`src/engine/GuardrailsEngine.js`)

Core orchestration engine that coordinates all security components:

```javascript
import { GuardrailsEngine } from './src/engine/GuardrailsEngine.js';

const engine = new GuardrailsEngine({
  enableInputValidation: true,
  enableOutputFiltering: true,
  enablePolicyEnforcement: true,
  enableAuditLogging: true,
  enableRateLimiting: true,
  maxRequestsPerMinute: 60,
});

// Process incoming request
const result = await engine.processInput(request, { userId: 'user123' });

// Filter outgoing response
const filtered = await engine.processOutput(response, context);
```

### InputValidator (`src/validators/InputValidator.js`)

Validates and sanitizes incoming requests:

- Pattern matching for blocked content
- Size and token limits
- Character encoding validation
- SQL injection detection
- XSS prevention

### OutputFilter (`src/filters/OutputFilter.js`)

Filters and redacts sensitive information from outputs:

- PII detection and redaction (SSN, credit cards, emails)
- API key/secret detection
- Custom pattern redaction
- Configurable replacement text

### PolicyEngine (`src/policies/PolicyEngine.js`)

Enforces custom security policies:

- Allow/deny lists for operations
- Domain restrictions
- Resource access controls
- Custom policy rules

### AuditLogger (`src/audit/AuditLogger.js`)

Comprehensive audit logging:

- Request/response logging
- Policy violation tracking
- Rate limit events
- Searchable log queries

## Configuration

```javascript
const config = {
  // Feature toggles
  enableInputValidation: true,
  enableOutputFiltering: true,
  enablePolicyEnforcement: true,
  enableAuditLogging: true,
  enableRateLimiting: true,

  // Rate limiting
  maxRequestsPerMinute: 60,
  maxTokensPerRequest: 100000,

  // Security patterns
  blockedPatterns: [
    /password\s*[:=]/i,
    /api[_-]?key/i,
  ],

  // Domain restrictions
  allowedDomains: ['api.example.com'],

  // Sensitive data patterns for redaction
  sensitiveDataPatterns: [
    { pattern: /\b\d{3}-\d{2}-\d{4}\b/, replacement: '[SSN REDACTED]' },
    { pattern: /\b\d{16}\b/, replacement: '[CARD REDACTED]' },
  ],
};
```

## Installation

```bash
cd ~/guardrails-mcp-server
npm install
```

## Usage with Claude Code

Add to `~/.claude.json`:

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

## Use Cases

### Enterprise AI Deployments

- Ensure all AI interactions comply with security policies
- Prevent data leakage through output filtering
- Maintain audit trails for compliance

### Multi-Tenant Systems

- Rate limiting per user/tenant
- Policy isolation between tenants
- Usage tracking and billing

### Regulated Industries

- Healthcare: HIPAA compliance with PHI detection
- Finance: PCI-DSS with card number redaction
- Government: Data classification enforcement

## API

### processInput(request, context)

Process and validate an incoming request.

**Returns:**
```javascript
{
  allowed: boolean,
  requestId: string,
  request: object,  // Sanitized request
  processingTime: number,
  // If blocked:
  reason: string,
  code: 'RATE_LIMIT' | 'VALIDATION_ERROR' | 'POLICY_VIOLATION',
  violations: array,
}
```

### processOutput(response, context)

Filter and redact sensitive data from a response.

**Returns:**
```javascript
{
  filtered: boolean,
  response: object,  // Filtered response
  redactions: array, // List of redactions applied
  processingTime: number,
}
```

### getStats()

Get current engine statistics.

### getAuditLogs(filter)

Query audit logs with optional filtering.

## Files

```
guardrails-mcp-server/
├── package.json
├── README.md
├── src/
│   ├── engine/
│   │   └── GuardrailsEngine.js    # Core engine
│   ├── validators/
│   │   └── InputValidator.js      # Input validation
│   ├── filters/
│   │   └── OutputFilter.js        # Output filtering
│   ├── policies/
│   │   └── PolicyEngine.js        # Policy enforcement
│   └── audit/
│       └── AuditLogger.js         # Audit logging
├── tests/
└── docs/
```

## Author

Matthew Karsten - Purple Squirrel Media

## License

MIT
