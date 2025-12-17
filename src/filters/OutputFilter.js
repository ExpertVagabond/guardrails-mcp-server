/**
 * OutputFilter - Filters and redacts sensitive information from outputs
 *
 * Provides:
 * - PII redaction
 * - Secret/credential filtering
 * - Content policy enforcement
 * - Custom pattern masking
 */

export class OutputFilter {
  constructor(config = {}) {
    this.config = config;

    // Sensitive data patterns with redaction masks
    this.sensitivePatterns = [
      {
        name: 'SSN',
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        mask: '[SSN REDACTED]',
      },
      {
        name: 'CreditCard',
        pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
        mask: '[CARD REDACTED]',
      },
      {
        name: 'Email',
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        mask: '[EMAIL REDACTED]',
        partialMask: (match) => {
          const [local, domain] = match.split('@');
          return `${local[0]}***@${domain}`;
        },
      },
      {
        name: 'Phone',
        pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
        mask: '[PHONE REDACTED]',
        partialMask: (match) => match.replace(/\d(?=\d{4})/g, '*'),
      },
      {
        name: 'IPAddress',
        pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        mask: '[IP REDACTED]',
      },
      {
        name: 'APIKey',
        pattern: /\b(?:sk-|pk-|api[_-]?key[_-]?)[a-zA-Z0-9]{20,}\b/gi,
        mask: '[API_KEY REDACTED]',
      },
      {
        name: 'AWSAccessKey',
        pattern: /\bAKIA[0-9A-Z]{16}\b/g,
        mask: '[AWS_KEY REDACTED]',
      },
      {
        name: 'AWSSecretKey',
        pattern: /\b[A-Za-z0-9/+=]{40}\b/g,
        mask: '[SECRET REDACTED]',
        context: /aws|secret|key/i, // Only match if context suggests it's a secret
      },
      {
        name: 'JWTToken',
        pattern: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
        mask: '[JWT REDACTED]',
      },
      {
        name: 'Password',
        pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"]?[^\s'"]+['"]?/gi,
        mask: '[PASSWORD REDACTED]',
      },
      {
        name: 'PrivateKey',
        pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
        mask: '[PRIVATE_KEY REDACTED]',
      },
      {
        name: 'ConnectionString',
        pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s]+/gi,
        mask: '[CONNECTION_STRING REDACTED]',
      },
    ];

    // Harmful content patterns
    this.harmfulPatterns = [
      {
        name: 'MaliciousCode',
        pattern: /(?:rm\s+-rf|format\s+c:|del\s+\/[fqs]|shutdown|reboot|kill\s+-9)/gi,
        action: 'block',
        message: 'Potentially harmful command detected',
      },
      {
        name: 'SQLInjection',
        pattern: /(?:UNION\s+SELECT|DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)/gi,
        action: 'warn',
        message: 'SQL injection pattern detected',
      },
    ];

    // Custom redaction patterns from config
    this.customPatterns = config.sensitiveDataPatterns || [];
  }

  /**
   * Filter response content
   * @param {Object|string} response - The response to filter
   * @param {Object} context - Additional context
   * @returns {Object} - Filter result
   */
  async filter(response, context = {}) {
    const redactions = [];
    let modified = false;

    // Extract and process text content
    let filteredResponse;
    if (typeof response === 'string') {
      const result = this.filterText(response);
      filteredResponse = result.text;
      redactions.push(...result.redactions);
      modified = result.modified;
    } else {
      filteredResponse = await this.filterObject(response, redactions);
      modified = redactions.length > 0;
    }

    // Check for harmful content
    const textContent = typeof filteredResponse === 'string'
      ? filteredResponse
      : JSON.stringify(filteredResponse);

    const harmfulCheck = this.checkHarmfulContent(textContent);
    if (harmfulCheck.found) {
      redactions.push(...harmfulCheck.findings.map(f => ({
        type: 'HARMFUL_CONTENT',
        name: f.name,
        action: f.action,
        message: f.message,
      })));

      // Block if any harmful pattern has action='block'
      if (harmfulCheck.findings.some(f => f.action === 'block')) {
        return {
          response: null,
          modified: true,
          blocked: true,
          redactions,
          message: 'Response blocked due to harmful content',
        };
      }
    }

    return {
      response: filteredResponse,
      modified,
      blocked: false,
      redactions,
    };
  }

  /**
   * Filter text content
   */
  filterText(text) {
    let filtered = text;
    const redactions = [];
    let modified = false;

    // Apply sensitive data patterns
    for (const pattern of [...this.sensitivePatterns, ...this.customPatterns]) {
      const matches = filtered.match(pattern.pattern);
      if (matches) {
        for (const match of matches) {
          // Check context if specified
          if (pattern.context && !pattern.context.test(filtered)) {
            continue;
          }

          const replacement = this.config.partialRedaction && pattern.partialMask
            ? pattern.partialMask(match)
            : pattern.mask;

          filtered = filtered.replace(match, replacement);
          redactions.push({
            type: 'SENSITIVE_DATA',
            name: pattern.name,
            originalLength: match.length,
          });
          modified = true;
        }
      }
    }

    return { text: filtered, redactions, modified };
  }

  /**
   * Filter object recursively
   */
  async filterObject(obj, redactions = []) {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      const result = this.filterText(obj);
      redactions.push(...result.redactions);
      return result.text;
    }

    if (Array.isArray(obj)) {
      return Promise.all(obj.map(item => this.filterObject(item, redactions)));
    }

    if (typeof obj === 'object') {
      const filtered = {};
      for (const [key, value] of Object.entries(obj)) {
        // Check if key itself is sensitive
        const sensitiveKeys = ['password', 'secret', 'apiKey', 'token', 'credential', 'auth'];
        const isSensitiveKey = sensitiveKeys.some(k =>
          key.toLowerCase().includes(k.toLowerCase())
        );

        if (isSensitiveKey && typeof value === 'string') {
          filtered[key] = '[REDACTED]';
          redactions.push({
            type: 'SENSITIVE_KEY',
            name: key,
          });
        } else {
          filtered[key] = await this.filterObject(value, redactions);
        }
      }
      return filtered;
    }

    return obj;
  }

  /**
   * Check for harmful content
   */
  checkHarmfulContent(text) {
    const findings = [];

    for (const pattern of this.harmfulPatterns) {
      if (pattern.pattern.test(text)) {
        findings.push({
          name: pattern.name,
          action: pattern.action,
          message: pattern.message,
        });
      }
    }

    return {
      found: findings.length > 0,
      findings,
    };
  }

  /**
   * Update configuration
   */
  updateConfig(config) {
    this.config = { ...this.config, ...config };
    if (config.sensitiveDataPatterns) {
      this.customPatterns = config.sensitiveDataPatterns;
    }
  }

  /**
   * Add a custom sensitive pattern
   */
  addSensitivePattern(name, pattern, mask) {
    this.sensitivePatterns.push({
      name,
      pattern: typeof pattern === 'string' ? new RegExp(pattern, 'g') : pattern,
      mask,
    });
  }

  /**
   * Add a custom harmful pattern
   */
  addHarmfulPattern(name, pattern, action = 'warn', message = '') {
    this.harmfulPatterns.push({
      name,
      pattern: typeof pattern === 'string' ? new RegExp(pattern, 'gi') : pattern,
      action,
      message: message || `${name} pattern detected`,
    });
  }
}

export default OutputFilter;
