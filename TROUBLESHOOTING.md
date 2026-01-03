# Troubleshooting Guide

Common issues and solutions for the AI Guardrails MCP Server.

## Rate Limiting Issues

### `RATE_LIMIT` - Request blocked

**Cause**: Too many requests in the time window.

**Solutions**:
1. Increase `maxRequestsPerMinute` in config
2. Add delays between rapid requests
3. Check if legitimate usage or potential abuse

**Example config adjustment**:
```javascript
const engine = new GuardrailsEngine({
  maxRequestsPerMinute: 120,  // Increase from default 60
});
```

### Rate limits applying to wrong users

**Cause**: User context not being passed correctly.

**Solution**: Always include `userId` in context:
```javascript
const result = await engine.processInput(request, {
  userId: 'unique-user-id',
  tenantId: 'tenant-123'  // For multi-tenant setups
});
```

## Input Validation Issues

### `VALIDATION_ERROR` - Request rejected

**Cause**: Input matched a blocked pattern.

**Solutions**:
1. Check which pattern triggered the block
2. Review `blockedPatterns` configuration
3. Add exceptions for legitimate use cases

**Checking violation details**:
```javascript
if (!result.allowed) {
  console.log('Violations:', result.violations);
  // [{pattern: '...', message: '...'}]
}
```

### False positives on valid content

**Cause**: Pattern too broad.

**Solutions**:
1. Make patterns more specific
2. Add word boundaries: `\bpassword\b` instead of `password`
3. Use negative lookahead for exceptions

**Example**:
```javascript
blockedPatterns: [
  // Too broad - blocks "password reset"
  /password/i,

  // Better - only blocks password disclosure
  /password\s*[:=]\s*\S+/i,
]
```

### Token limit exceeded

**Cause**: Request too large.

**Solution**: Adjust `maxTokensPerRequest`:
```javascript
const engine = new GuardrailsEngine({
  maxTokensPerRequest: 200000,  // Increase limit
});
```

## Output Filtering Issues

### Sensitive data not being redacted

**Cause**: Pattern doesn't match the format.

**Solutions**:
1. Check regex pattern syntax
2. Test patterns with sample data
3. Add additional patterns for variations

**Common patterns**:
```javascript
sensitiveDataPatterns: [
  // SSN variations
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/, replacement: '[SSN]' },
  { pattern: /\b\d{9}\b/, replacement: '[SSN]' },

  // Credit cards (13-19 digits)
  { pattern: /\b\d{13,19}\b/, replacement: '[CARD]' },
  { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, replacement: '[CARD]' },

  // Email addresses
  { pattern: /\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g, replacement: '[EMAIL]' },

  // API keys (common formats)
  { pattern: /\b(sk|pk|api)[_-][a-zA-Z0-9]{20,}\b/g, replacement: '[API_KEY]' },
]
```

### Over-redaction of content

**Cause**: Patterns too aggressive.

**Solutions**:
1. Use more specific patterns
2. Add context requirements
3. Use word boundaries

### Performance slow on large outputs

**Cause**: Many regex patterns or large text.

**Solutions**:
1. Compile regex patterns once (use RegExp objects)
2. Use simpler patterns where possible
3. Consider chunking large outputs

## Policy Engine Issues

### `POLICY_VIOLATION` - Action blocked

**Cause**: Request violates a configured policy.

**Check policy details**:
```javascript
if (!result.allowed && result.code === 'POLICY_VIOLATION') {
  console.log('Policy violated:', result.reason);
  console.log('Violations:', result.violations);
}
```

### Domain restrictions not working

**Cause**: URL parsing or matching issue.

**Solution**: Check domain format:
```javascript
// Correct
allowedDomains: ['api.example.com', 'cdn.example.com']

// Wrong - don't include protocol
allowedDomains: ['https://api.example.com']
```

### Custom policies not executing

**Cause**: Policy syntax or registration issue.

**Solution**: Verify policy structure:
```javascript
const customPolicy = {
  name: 'my-policy',
  description: 'Custom validation',
  evaluate: (request, context) => {
    if (/* violation condition */) {
      return {
        allowed: false,
        reason: 'Policy violation description',
      };
    }
    return { allowed: true };
  }
};
```

## Audit Logging Issues

### Logs not being written

**Cause**: Audit logging disabled or path issue.

**Solutions**:
1. Verify `enableAuditLogging: true`
2. Check log file path permissions
3. Ensure disk has space

### Log queries returning empty

**Cause**: Filter too restrictive or no matching logs.

**Solution**: Broaden filter:
```javascript
// Start with no filter
const logs = await engine.getAuditLogs({});

// Then narrow down
const logs = await engine.getAuditLogs({
  startTime: new Date(Date.now() - 3600000),  // Last hour
  userId: 'user123',
});
```

### Log file growing too large

**Solutions**:
1. Implement log rotation
2. Set up external log aggregation
3. Configure retention policy

## Configuration Issues

### Engine not initializing

**Cause**: Invalid configuration object.

**Solution**: Check all required fields:
```javascript
const engine = new GuardrailsEngine({
  enableInputValidation: true,
  enableOutputFiltering: true,
  enablePolicyEnforcement: true,
  enableAuditLogging: true,
  enableRateLimiting: true,
  maxRequestsPerMinute: 60,
});
```

### Hot reload not working

**Cause**: Config changes not detected.

**Solution**: Implement reload:
```javascript
// Reload configuration
engine.updateConfig(newConfig);

// Or recreate engine
engine = new GuardrailsEngine(newConfig);
```

## MCP Server Issues

### Server not appearing in Claude Code

**Solutions**:
1. Verify `~/.claude.json` syntax
2. Check path to `index.js`
3. Restart Claude Code
4. Test: `node /path/to/guardrails-mcp-server/index.js`

### Module not found errors

**Solution**:
```bash
cd ~/guardrails-mcp-server
npm install
```

## Debugging

### Enable debug mode

```javascript
const engine = new GuardrailsEngine({
  // ... other config
  debug: true,  // Verbose logging
});
```

### Test individual components

```javascript
// Test input validator
const validator = new InputValidator(config);
const result = validator.validate(testInput);

// Test output filter
const filter = new OutputFilter(config);
const result = filter.filter(testOutput);
```

### View engine statistics

```javascript
const stats = engine.getStats();
console.log('Requests processed:', stats.totalRequests);
console.log('Requests blocked:', stats.blockedRequests);
console.log('Rate limit hits:', stats.rateLimitHits);
```

## Getting Help

- [GitHub Issues](https://github.com/PurpleSquirrelMedia/guardrails-mcp-server/issues)
- [OWASP Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
