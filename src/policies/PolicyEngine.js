/**
 * PolicyEngine - Enforces security and usage policies
 *
 * Provides:
 * - Role-based access control
 * - Resource access policies
 * - Time-based restrictions
 * - Quota management
 * - Custom rule evaluation
 */

export class PolicyEngine {
  constructor(config = {}) {
    this.config = config;
    this.policies = new Map();
    this.quotas = new Map();

    // Initialize default policies
    this.initializeDefaultPolicies();
  }

  /**
   * Initialize default security policies
   */
  initializeDefaultPolicies() {
    // Default: Block file system access to sensitive paths
    this.addPolicy({
      id: 'block-sensitive-paths',
      name: 'Block Sensitive File Paths',
      description: 'Prevents access to sensitive system paths',
      enabled: true,
      priority: 100,
      condition: (request, context) => {
        const text = JSON.stringify(request).toLowerCase();
        const sensitivePaths = [
          '/etc/passwd', '/etc/shadow', '/etc/hosts',
          '.ssh/', '.aws/', '.env',
          'id_rsa', 'credentials',
          '/var/log/', '/proc/', '/sys/',
        ];
        return sensitivePaths.some(path => text.includes(path));
      },
      action: 'deny',
      message: 'Access to sensitive system paths is not allowed',
    });

    // Default: Block potentially dangerous tool calls
    this.addPolicy({
      id: 'block-dangerous-tools',
      name: 'Block Dangerous Tool Calls',
      description: 'Prevents execution of potentially dangerous operations',
      enabled: true,
      priority: 90,
      condition: (request, context) => {
        const toolName = request.name || request.tool || '';
        const dangerousTools = [
          'shell', 'exec', 'system', 'spawn',
          'eval', 'run_command', 'execute',
        ];
        return dangerousTools.some(t =>
          toolName.toLowerCase().includes(t)
        );
      },
      action: 'deny',
      message: 'Execution of shell commands requires explicit authorization',
    });

    // Default: Require authentication for sensitive operations
    this.addPolicy({
      id: 'require-auth-sensitive',
      name: 'Require Auth for Sensitive Operations',
      description: 'Requires authentication for sensitive operations',
      enabled: true,
      priority: 80,
      condition: (request, context) => {
        const sensitiveOps = ['delete', 'remove', 'drop', 'truncate', 'destroy'];
        const text = JSON.stringify(request).toLowerCase();
        const isSensitive = sensitiveOps.some(op => text.includes(op));
        return isSensitive && !context.authenticated;
      },
      action: 'deny',
      message: 'Authentication required for sensitive operations',
    });

    // Default: Rate limit by user
    this.addPolicy({
      id: 'user-quota',
      name: 'User Request Quota',
      description: 'Enforces per-user request quotas',
      enabled: true,
      priority: 70,
      condition: (request, context) => {
        if (!context.userId) return false;
        const quota = this.getQuota(context.userId);
        return quota.used >= quota.limit;
      },
      action: 'deny',
      message: 'User quota exceeded',
    });

    // Default: Block during maintenance windows
    this.addPolicy({
      id: 'maintenance-window',
      name: 'Maintenance Window',
      description: 'Blocks requests during maintenance windows',
      enabled: false, // Disabled by default
      priority: 200,
      condition: (request, context) => {
        const maintenanceWindows = this.config.maintenanceWindows || [];
        const now = new Date();
        return maintenanceWindows.some(window => {
          const start = new Date(window.start);
          const end = new Date(window.end);
          return now >= start && now <= end;
        });
      },
      action: 'deny',
      message: 'System is under maintenance',
    });

    // Default: Allow-list for external URLs
    this.addPolicy({
      id: 'url-allowlist',
      name: 'URL Allow List',
      description: 'Only allows access to approved external URLs',
      enabled: false, // Disabled by default
      priority: 60,
      condition: (request, context) => {
        const allowedDomains = this.config.allowedDomains || [];
        if (allowedDomains.length === 0) return false;

        const urlPattern = /https?:\/\/([^\/\s]+)/gi;
        const text = JSON.stringify(request);
        const matches = text.matchAll(urlPattern);

        for (const match of matches) {
          const domain = match[1].toLowerCase();
          const isAllowed = allowedDomains.some(allowed =>
            domain === allowed || domain.endsWith('.' + allowed)
          );
          if (!isAllowed) return true; // Block if not in allowlist
        }
        return false;
      },
      action: 'deny',
      message: 'External URL not in allowed list',
    });
  }

  /**
   * Evaluate all policies against a request
   * @param {Object} request - The request to evaluate
   * @param {Object} context - Additional context
   * @returns {Object} - Evaluation result
   */
  async evaluate(request, context = {}) {
    // Get enabled policies sorted by priority (higher first)
    const enabledPolicies = Array.from(this.policies.values())
      .filter(p => p.enabled)
      .sort((a, b) => b.priority - a.priority);

    for (const policy of enabledPolicies) {
      try {
        const conditionResult = await Promise.resolve(
          policy.condition(request, context)
        );

        if (conditionResult) {
          // Policy condition matched
          if (policy.action === 'deny') {
            return {
              allowed: false,
              reason: policy.message,
              violatedPolicy: {
                id: policy.id,
                name: policy.name,
              },
            };
          } else if (policy.action === 'warn') {
            // Log warning but allow
            console.warn(`Policy warning [${policy.id}]: ${policy.message}`);
          } else if (policy.action === 'modify') {
            // Allow policy to modify request
            if (policy.modify) {
              request = await Promise.resolve(policy.modify(request, context));
            }
          }
        }
      } catch (error) {
        console.error(`Policy evaluation error [${policy.id}]:`, error.message);
        // Fail closed on policy evaluation errors
        if (this.config.failClosed !== false) {
          return {
            allowed: false,
            reason: 'Policy evaluation error',
            error: error.message,
          };
        }
      }
    }

    return { allowed: true };
  }

  /**
   * Add a policy
   */
  addPolicy(policy) {
    if (!policy.id) {
      policy.id = `policy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }
    this.policies.set(policy.id, {
      enabled: true,
      priority: 50,
      action: 'deny',
      ...policy,
    });
    return policy.id;
  }

  /**
   * Remove a policy
   */
  removePolicy(policyId) {
    return this.policies.delete(policyId);
  }

  /**
   * Enable/disable a policy
   */
  setEnabled(policyId, enabled) {
    const policy = this.policies.get(policyId);
    if (policy) {
      policy.enabled = enabled;
      return true;
    }
    return false;
  }

  /**
   * Get all policies
   */
  getPolicies() {
    return Array.from(this.policies.values());
  }

  /**
   * Get policy by ID
   */
  getPolicy(policyId) {
    return this.policies.get(policyId);
  }

  /**
   * Update configuration
   */
  updateConfig(config) {
    this.config = { ...this.config, ...config };
  }

  /**
   * Set quota for a user
   */
  setQuota(userId, limit) {
    this.quotas.set(userId, { limit, used: 0, resetAt: Date.now() + 86400000 });
  }

  /**
   * Get quota for a user
   */
  getQuota(userId) {
    if (!this.quotas.has(userId)) {
      this.setQuota(userId, this.config.defaultQuota || 1000);
    }

    const quota = this.quotas.get(userId);

    // Reset quota if period expired
    if (Date.now() > quota.resetAt) {
      quota.used = 0;
      quota.resetAt = Date.now() + 86400000;
    }

    return quota;
  }

  /**
   * Increment quota usage
   */
  incrementQuota(userId, amount = 1) {
    const quota = this.getQuota(userId);
    quota.used += amount;
  }

  /**
   * Create a policy from a simple rule definition
   */
  createSimplePolicy(rule) {
    const { id, name, description, pattern, action = 'deny', message, field = 'all' } = rule;

    return this.addPolicy({
      id,
      name,
      description,
      enabled: true,
      priority: 50,
      action,
      message: message || `Rule ${name} violated`,
      condition: (request, context) => {
        let text;
        if (field === 'all') {
          text = JSON.stringify(request);
        } else {
          text = request[field] || '';
        }

        const regex = typeof pattern === 'string' ? new RegExp(pattern, 'i') : pattern;
        return regex.test(text);
      },
    });
  }

  /**
   * Load policies from JSON configuration
   */
  loadPolicies(policiesConfig) {
    for (const config of policiesConfig) {
      if (config.type === 'simple') {
        this.createSimplePolicy(config);
      } else {
        this.addPolicy(config);
      }
    }
  }
}

export default PolicyEngine;
