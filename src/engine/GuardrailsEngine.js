/**
 * GuardrailsEngine - Core engine for AI agent security and validation
 *
 * Provides:
 * - Input validation and sanitization
 * - Output filtering and redaction
 * - Policy enforcement
 * - Audit logging
 * - Rate limiting
 */

import { InputValidator } from '../validators/InputValidator.js';
import { OutputFilter } from '../filters/OutputFilter.js';
import { PolicyEngine } from '../policies/PolicyEngine.js';
import { AuditLogger } from '../audit/AuditLogger.js';

export class GuardrailsEngine {
  constructor(config = {}) {
    this.config = {
      // Default configuration
      enableInputValidation: true,
      enableOutputFiltering: true,
      enablePolicyEnforcement: true,
      enableAuditLogging: true,
      enableRateLimiting: true,
      maxRequestsPerMinute: 60,
      maxTokensPerRequest: 100000,
      blockedPatterns: [],
      allowedDomains: [],
      sensitiveDataPatterns: [],
      ...config,
    };

    // Initialize components
    this.inputValidator = new InputValidator(this.config);
    this.outputFilter = new OutputFilter(this.config);
    this.policyEngine = new PolicyEngine(this.config);
    this.auditLogger = new AuditLogger(this.config);

    // Rate limiting state
    this.requestCounts = new Map();
    this.lastCleanup = Date.now();
  }

  /**
   * Process an incoming request through all guardrails
   * @param {Object} request - The request to process
   * @param {Object} context - Additional context (user, session, etc.)
   * @returns {Object} - Processing result with status and modified request
   */
  async processInput(request, context = {}) {
    const startTime = Date.now();
    const requestId = this.generateRequestId();

    try {
      // 1. Rate limiting check
      if (this.config.enableRateLimiting) {
        const rateLimitResult = this.checkRateLimit(context.userId || 'anonymous');
        if (!rateLimitResult.allowed) {
          await this.auditLogger.log({
            requestId,
            type: 'RATE_LIMIT_EXCEEDED',
            context,
            timestamp: new Date().toISOString(),
          });
          return {
            allowed: false,
            reason: 'Rate limit exceeded',
            code: 'RATE_LIMIT',
            retryAfter: rateLimitResult.retryAfter,
          };
        }
      }

      // 2. Input validation
      if (this.config.enableInputValidation) {
        const validationResult = await this.inputValidator.validate(request, context);
        if (!validationResult.valid) {
          await this.auditLogger.log({
            requestId,
            type: 'INPUT_VALIDATION_FAILED',
            violations: validationResult.violations,
            context,
            timestamp: new Date().toISOString(),
          });
          return {
            allowed: false,
            reason: 'Input validation failed',
            code: 'VALIDATION_ERROR',
            violations: validationResult.violations,
          };
        }
        // Apply sanitization
        request = validationResult.sanitizedRequest || request;
      }

      // 3. Policy enforcement
      if (this.config.enablePolicyEnforcement) {
        const policyResult = await this.policyEngine.evaluate(request, context);
        if (!policyResult.allowed) {
          await this.auditLogger.log({
            requestId,
            type: 'POLICY_VIOLATION',
            policy: policyResult.violatedPolicy,
            context,
            timestamp: new Date().toISOString(),
          });
          return {
            allowed: false,
            reason: policyResult.reason,
            code: 'POLICY_VIOLATION',
            policy: policyResult.violatedPolicy,
          };
        }
      }

      // 4. Log successful processing
      if (this.config.enableAuditLogging) {
        await this.auditLogger.log({
          requestId,
          type: 'INPUT_PROCESSED',
          processingTime: Date.now() - startTime,
          context,
          timestamp: new Date().toISOString(),
        });
      }

      return {
        allowed: true,
        requestId,
        request,
        processingTime: Date.now() - startTime,
      };

    } catch (error) {
      await this.auditLogger.log({
        requestId,
        type: 'PROCESSING_ERROR',
        error: error.message,
        context,
        timestamp: new Date().toISOString(),
      });
      return {
        allowed: false,
        reason: 'Internal processing error',
        code: 'INTERNAL_ERROR',
        error: error.message,
      };
    }
  }

  /**
   * Process an outgoing response through output filters
   * @param {Object} response - The response to filter
   * @param {Object} context - Additional context
   * @returns {Object} - Filtered response
   */
  async processOutput(response, context = {}) {
    const startTime = Date.now();
    const requestId = context.requestId || this.generateRequestId();

    try {
      if (!this.config.enableOutputFiltering) {
        return { filtered: false, response };
      }

      const filterResult = await this.outputFilter.filter(response, context);

      if (this.config.enableAuditLogging) {
        await this.auditLogger.log({
          requestId,
          type: 'OUTPUT_FILTERED',
          redactionsApplied: filterResult.redactions?.length || 0,
          processingTime: Date.now() - startTime,
          context,
          timestamp: new Date().toISOString(),
        });
      }

      return {
        filtered: filterResult.modified,
        response: filterResult.response,
        redactions: filterResult.redactions,
        processingTime: Date.now() - startTime,
      };

    } catch (error) {
      await this.auditLogger.log({
        requestId,
        type: 'OUTPUT_FILTER_ERROR',
        error: error.message,
        context,
        timestamp: new Date().toISOString(),
      });
      return {
        filtered: false,
        response,
        error: error.message,
      };
    }
  }

  /**
   * Check rate limit for a user
   */
  checkRateLimit(userId) {
    this.cleanupRateLimits();

    const now = Date.now();
    const windowStart = now - 60000; // 1 minute window

    if (!this.requestCounts.has(userId)) {
      this.requestCounts.set(userId, []);
    }

    const userRequests = this.requestCounts.get(userId);
    const recentRequests = userRequests.filter(t => t > windowStart);
    this.requestCounts.set(userId, recentRequests);

    if (recentRequests.length >= this.config.maxRequestsPerMinute) {
      const oldestRequest = Math.min(...recentRequests);
      const retryAfter = Math.ceil((oldestRequest + 60000 - now) / 1000);
      return { allowed: false, retryAfter };
    }

    recentRequests.push(now);
    return { allowed: true };
  }

  /**
   * Cleanup old rate limit entries
   */
  cleanupRateLimits() {
    const now = Date.now();
    if (now - this.lastCleanup < 60000) return;

    const windowStart = now - 60000;
    for (const [userId, requests] of this.requestCounts.entries()) {
      const recent = requests.filter(t => t > windowStart);
      if (recent.length === 0) {
        this.requestCounts.delete(userId);
      } else {
        this.requestCounts.set(userId, recent);
      }
    }
    this.lastCleanup = now;
  }

  /**
   * Generate a unique request ID
   */
  generateRequestId() {
    return `gr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get current engine statistics
   */
  getStats() {
    return {
      activeUsers: this.requestCounts.size,
      totalRequests: this.auditLogger.getRequestCount(),
      blockedRequests: this.auditLogger.getBlockedCount(),
      config: {
        inputValidation: this.config.enableInputValidation,
        outputFiltering: this.config.enableOutputFiltering,
        policyEnforcement: this.config.enablePolicyEnforcement,
        rateLimiting: this.config.enableRateLimiting,
      },
    };
  }

  /**
   * Update engine configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.inputValidator.updateConfig(this.config);
    this.outputFilter.updateConfig(this.config);
    this.policyEngine.updateConfig(this.config);
  }

  /**
   * Add a custom policy
   */
  addPolicy(policy) {
    return this.policyEngine.addPolicy(policy);
  }

  /**
   * Remove a policy
   */
  removePolicy(policyId) {
    return this.policyEngine.removePolicy(policyId);
  }

  /**
   * Get audit logs
   */
  getAuditLogs(filter = {}) {
    return this.auditLogger.getLogs(filter);
  }
}

export default GuardrailsEngine;
