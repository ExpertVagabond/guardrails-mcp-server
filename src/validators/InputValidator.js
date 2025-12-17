/**
 * InputValidator - Validates and sanitizes incoming requests
 *
 * Checks for:
 * - Prompt injection attempts
 * - Malicious code patterns
 * - PII/sensitive data
 * - Content length limits
 * - Blocked keywords/patterns
 */

export class InputValidator {
  constructor(config = {}) {
    this.config = config;

    // Prompt injection patterns
    this.injectionPatterns = [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/i,
      /disregard\s+(all\s+)?(previous|prior|above)/i,
      /forget\s+(everything|all|your)\s+(you|instructions?|rules?)/i,
      /you\s+are\s+now\s+(a|an|the)\s+/i,
      /pretend\s+(you\s+are|to\s+be)/i,
      /act\s+as\s+(if|though|a|an)/i,
      /jailbreak/i,
      /DAN\s+mode/i,
      /developer\s+mode\s+(enabled|on|activated)/i,
      /bypass\s+(safety|security|filters?|guardrails?)/i,
      /override\s+(system|safety|security)/i,
      /\[SYSTEM\]|\[ADMIN\]|\[ROOT\]/i,
      /```system|```admin/i,
    ];

    // Malicious code patterns
    this.codePatterns = [
      /eval\s*\(/i,
      /exec\s*\(/i,
      /system\s*\(/i,
      /subprocess/i,
      /os\.system/i,
      /child_process/i,
      /spawn\s*\(/i,
      /import\s+os\b/i,
      /require\s*\(\s*['"]child_process['"]\s*\)/i,
      /__import__\s*\(/i,
      /\bsh\s+-c\b/i,
      /\bbash\s+-c\b/i,
      /;\s*rm\s+-rf/i,
      /&&\s*rm\s+-rf/i,
      /\|\s*sh\b/i,
      /\$\(.*\)/,
      /`.*`/,
    ];

    // PII patterns
    this.piiPatterns = [
      { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
      { name: 'CreditCard', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/ },
      { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g },
      { name: 'Phone', pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/ },
      { name: 'IPAddress', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
      { name: 'APIKey', pattern: /\b(?:sk-|pk-|api[_-]?key[_-]?)[a-zA-Z0-9]{20,}\b/i },
      { name: 'AWSKey', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
      { name: 'Password', pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*\S+/i },
    ];

    // Blocked keywords (configurable)
    this.blockedKeywords = config.blockedKeywords || [];
  }

  /**
   * Validate an incoming request
   * @param {Object} request - The request to validate
   * @param {Object} context - Additional context
   * @returns {Object} - Validation result
   */
  async validate(request, context = {}) {
    const violations = [];
    let sanitizedRequest = JSON.parse(JSON.stringify(request));

    // Extract text content from request
    const textContent = this.extractTextContent(request);

    // 1. Check content length
    if (textContent.length > (this.config.maxInputLength || 100000)) {
      violations.push({
        type: 'LENGTH_EXCEEDED',
        message: `Input exceeds maximum length of ${this.config.maxInputLength || 100000} characters`,
        severity: 'high',
      });
    }

    // 2. Check for prompt injection
    for (const pattern of this.injectionPatterns) {
      if (pattern.test(textContent)) {
        violations.push({
          type: 'PROMPT_INJECTION',
          message: 'Potential prompt injection detected',
          pattern: pattern.toString(),
          severity: 'critical',
        });
      }
    }

    // 3. Check for malicious code patterns
    for (const pattern of this.codePatterns) {
      if (pattern.test(textContent)) {
        violations.push({
          type: 'MALICIOUS_CODE',
          message: 'Potentially malicious code pattern detected',
          pattern: pattern.toString(),
          severity: 'high',
        });
      }
    }

    // 4. Check for PII (if configured to block)
    if (this.config.blockPII) {
      for (const pii of this.piiPatterns) {
        if (pii.pattern.test(textContent)) {
          violations.push({
            type: 'PII_DETECTED',
            message: `${pii.name} pattern detected in input`,
            severity: 'medium',
          });
        }
      }
    }

    // 5. Check blocked keywords
    for (const keyword of this.blockedKeywords) {
      const regex = typeof keyword === 'string'
        ? new RegExp(keyword, 'i')
        : keyword;
      if (regex.test(textContent)) {
        violations.push({
          type: 'BLOCKED_KEYWORD',
          message: 'Blocked keyword detected',
          severity: 'high',
        });
      }
    }

    // 6. Check custom patterns from config
    if (this.config.blockedPatterns) {
      for (const pattern of this.config.blockedPatterns) {
        const regex = typeof pattern === 'string'
          ? new RegExp(pattern, 'i')
          : pattern;
        if (regex.test(textContent)) {
          violations.push({
            type: 'BLOCKED_PATTERN',
            message: 'Blocked pattern detected',
            severity: 'high',
          });
        }
      }
    }

    // 7. Sanitize if configured
    if (this.config.sanitizeInput) {
      sanitizedRequest = this.sanitize(sanitizedRequest);
    }

    // Determine if valid based on violations
    const criticalViolations = violations.filter(v => v.severity === 'critical');
    const highViolations = violations.filter(v => v.severity === 'high');

    const valid = criticalViolations.length === 0 &&
      (this.config.allowHighSeverity || highViolations.length === 0);

    return {
      valid,
      violations,
      sanitizedRequest: valid ? sanitizedRequest : null,
      stats: {
        criticalCount: criticalViolations.length,
        highCount: highViolations.length,
        mediumCount: violations.filter(v => v.severity === 'medium').length,
      },
    };
  }

  /**
   * Extract text content from various request formats
   */
  extractTextContent(request) {
    if (typeof request === 'string') {
      return request;
    }

    const parts = [];

    // Handle common request structures
    if (request.prompt) parts.push(request.prompt);
    if (request.input) parts.push(request.input);
    if (request.text) parts.push(request.text);
    if (request.content) parts.push(request.content);
    if (request.message) parts.push(request.message);
    if (request.query) parts.push(request.query);

    // Handle messages array (chat format)
    if (Array.isArray(request.messages)) {
      for (const msg of request.messages) {
        if (msg.content) parts.push(msg.content);
      }
    }

    // Handle arguments object
    if (request.arguments) {
      parts.push(JSON.stringify(request.arguments));
    }

    return parts.join('\n');
  }

  /**
   * Sanitize request content
   */
  sanitize(request) {
    if (typeof request === 'string') {
      return this.sanitizeString(request);
    }

    const sanitized = { ...request };

    // Sanitize common fields
    const fieldsToSanitize = ['prompt', 'input', 'text', 'content', 'message', 'query'];
    for (const field of fieldsToSanitize) {
      if (sanitized[field] && typeof sanitized[field] === 'string') {
        sanitized[field] = this.sanitizeString(sanitized[field]);
      }
    }

    // Handle messages array
    if (Array.isArray(sanitized.messages)) {
      sanitized.messages = sanitized.messages.map(msg => ({
        ...msg,
        content: msg.content ? this.sanitizeString(msg.content) : msg.content,
      }));
    }

    return sanitized;
  }

  /**
   * Sanitize a string
   */
  sanitizeString(str) {
    let result = str;

    // Remove null bytes
    result = result.replace(/\0/g, '');

    // Normalize unicode
    result = result.normalize('NFC');

    // Remove control characters (except newlines and tabs)
    result = result.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    return result;
  }

  /**
   * Update configuration
   */
  updateConfig(config) {
    this.config = { ...this.config, ...config };
    if (config.blockedKeywords) {
      this.blockedKeywords = config.blockedKeywords;
    }
  }

  /**
   * Add a custom injection pattern
   */
  addInjectionPattern(pattern) {
    if (typeof pattern === 'string') {
      pattern = new RegExp(pattern, 'i');
    }
    this.injectionPatterns.push(pattern);
  }

  /**
   * Add a custom PII pattern
   */
  addPIIPattern(name, pattern) {
    this.piiPatterns.push({ name, pattern });
  }
}

export default InputValidator;
