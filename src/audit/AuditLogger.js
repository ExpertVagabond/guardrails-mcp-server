/**
 * AuditLogger - Comprehensive audit logging for guardrails events
 *
 * Provides:
 * - Event logging with timestamps
 * - Log rotation and retention
 * - Query and filtering
 * - Export capabilities
 * - Metrics aggregation
 */

export class AuditLogger {
  constructor(config = {}) {
    this.config = {
      maxLogSize: 10000, // Maximum logs to keep in memory
      retentionDays: 30,
      enableConsoleLog: false,
      logLevel: 'info', // 'debug', 'info', 'warn', 'error'
      ...config,
    };

    this.logs = [];
    this.metrics = {
      totalRequests: 0,
      blockedRequests: 0,
      filteredOutputs: 0,
      policyViolations: 0,
      validationErrors: 0,
      byType: {},
      byUser: {},
      byHour: {},
    };

    this.logLevels = { debug: 0, info: 1, warn: 2, error: 3 };
  }

  /**
   * Log an event
   * @param {Object} event - The event to log
   */
  async log(event) {
    const logEntry = {
      id: this.generateLogId(),
      timestamp: event.timestamp || new Date().toISOString(),
      level: event.level || 'info',
      ...event,
    };

    // Check log level
    if (this.logLevels[logEntry.level] < this.logLevels[this.config.logLevel]) {
      return logEntry.id;
    }

    // Add to logs
    this.logs.push(logEntry);

    // Update metrics
    this.updateMetrics(logEntry);

    // Console log if enabled
    if (this.config.enableConsoleLog) {
      this.consoleLog(logEntry);
    }

    // Rotate logs if needed
    if (this.logs.length > this.config.maxLogSize) {
      this.rotateLogs();
    }

    // Call external handler if configured
    if (this.config.externalHandler) {
      try {
        await this.config.externalHandler(logEntry);
      } catch (error) {
        console.error('External log handler error:', error.message);
      }
    }

    return logEntry.id;
  }

  /**
   * Update metrics based on log entry
   */
  updateMetrics(entry) {
    this.metrics.totalRequests++;

    // Update type counts
    if (!this.metrics.byType[entry.type]) {
      this.metrics.byType[entry.type] = 0;
    }
    this.metrics.byType[entry.type]++;

    // Update specific counters
    switch (entry.type) {
      case 'RATE_LIMIT_EXCEEDED':
      case 'POLICY_VIOLATION':
      case 'INPUT_VALIDATION_FAILED':
        this.metrics.blockedRequests++;
        break;
      case 'OUTPUT_FILTERED':
        if (entry.redactionsApplied > 0) {
          this.metrics.filteredOutputs++;
        }
        break;
    }

    if (entry.type === 'POLICY_VIOLATION') {
      this.metrics.policyViolations++;
    }

    if (entry.type === 'INPUT_VALIDATION_FAILED') {
      this.metrics.validationErrors++;
    }

    // Update user stats
    const userId = entry.context?.userId || 'anonymous';
    if (!this.metrics.byUser[userId]) {
      this.metrics.byUser[userId] = { total: 0, blocked: 0 };
    }
    this.metrics.byUser[userId].total++;
    if (['RATE_LIMIT_EXCEEDED', 'POLICY_VIOLATION', 'INPUT_VALIDATION_FAILED'].includes(entry.type)) {
      this.metrics.byUser[userId].blocked++;
    }

    // Update hourly stats
    const hour = new Date(entry.timestamp).toISOString().slice(0, 13);
    if (!this.metrics.byHour[hour]) {
      this.metrics.byHour[hour] = { total: 0, blocked: 0 };
    }
    this.metrics.byHour[hour].total++;
    if (['RATE_LIMIT_EXCEEDED', 'POLICY_VIOLATION', 'INPUT_VALIDATION_FAILED'].includes(entry.type)) {
      this.metrics.byHour[hour].blocked++;
    }
  }

  /**
   * Console log with formatting
   */
  consoleLog(entry) {
    const levelColors = {
      debug: '\x1b[36m', // cyan
      info: '\x1b[32m',  // green
      warn: '\x1b[33m',  // yellow
      error: '\x1b[31m', // red
    };
    const reset = '\x1b[0m';
    const color = levelColors[entry.level] || '';

    console.log(
      `${color}[${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.type}${reset}`,
      entry.requestId ? `(${entry.requestId})` : '',
      entry.message || ''
    );
  }

  /**
   * Rotate logs (remove oldest entries)
   */
  rotateLogs() {
    const cutoff = this.config.maxLogSize * 0.8;
    this.logs = this.logs.slice(-cutoff);
  }

  /**
   * Get logs with optional filtering
   * @param {Object} filter - Filter options
   */
  getLogs(filter = {}) {
    let results = [...this.logs];

    // Filter by type
    if (filter.type) {
      results = results.filter(l => l.type === filter.type);
    }

    // Filter by level
    if (filter.level) {
      const minLevel = this.logLevels[filter.level];
      results = results.filter(l => this.logLevels[l.level] >= minLevel);
    }

    // Filter by time range
    if (filter.startTime) {
      const start = new Date(filter.startTime);
      results = results.filter(l => new Date(l.timestamp) >= start);
    }
    if (filter.endTime) {
      const end = new Date(filter.endTime);
      results = results.filter(l => new Date(l.timestamp) <= end);
    }

    // Filter by user
    if (filter.userId) {
      results = results.filter(l => l.context?.userId === filter.userId);
    }

    // Filter by request ID
    if (filter.requestId) {
      results = results.filter(l => l.requestId === filter.requestId);
    }

    // Limit results
    if (filter.limit) {
      results = results.slice(-filter.limit);
    }

    return results;
  }

  /**
   * Get a single log by ID
   */
  getLog(logId) {
    return this.logs.find(l => l.id === logId);
  }

  /**
   * Get aggregated metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      blockRate: this.metrics.totalRequests > 0
        ? (this.metrics.blockedRequests / this.metrics.totalRequests * 100).toFixed(2)
        : 0,
      logsInMemory: this.logs.length,
    };
  }

  /**
   * Get request count
   */
  getRequestCount() {
    return this.metrics.totalRequests;
  }

  /**
   * Get blocked count
   */
  getBlockedCount() {
    return this.metrics.blockedRequests;
  }

  /**
   * Export logs to JSON
   */
  exportLogs(filter = {}) {
    const logs = this.getLogs(filter);
    return JSON.stringify(logs, null, 2);
  }

  /**
   * Clear all logs
   */
  clearLogs() {
    this.logs = [];
  }

  /**
   * Reset metrics
   */
  resetMetrics() {
    this.metrics = {
      totalRequests: 0,
      blockedRequests: 0,
      filteredOutputs: 0,
      policyViolations: 0,
      validationErrors: 0,
      byType: {},
      byUser: {},
      byHour: {},
    };
  }

  /**
   * Generate unique log ID
   */
  generateLogId() {
    return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Set external log handler
   */
  setExternalHandler(handler) {
    this.config.externalHandler = handler;
  }

  /**
   * Get summary report
   */
  getSummary(hours = 24) {
    const cutoff = new Date(Date.now() - hours * 3600000);
    const recentLogs = this.logs.filter(l => new Date(l.timestamp) >= cutoff);

    const summary = {
      period: `Last ${hours} hours`,
      totalRequests: recentLogs.length,
      blocked: recentLogs.filter(l =>
        ['RATE_LIMIT_EXCEEDED', 'POLICY_VIOLATION', 'INPUT_VALIDATION_FAILED'].includes(l.type)
      ).length,
      filtered: recentLogs.filter(l => l.type === 'OUTPUT_FILTERED').length,
      errors: recentLogs.filter(l => l.level === 'error').length,
      topViolations: this.getTopViolations(recentLogs, 5),
      uniqueUsers: new Set(recentLogs.map(l => l.context?.userId).filter(Boolean)).size,
    };

    summary.successRate = summary.totalRequests > 0
      ? ((summary.totalRequests - summary.blocked) / summary.totalRequests * 100).toFixed(2)
      : 100;

    return summary;
  }

  /**
   * Get top violations
   */
  getTopViolations(logs, limit = 5) {
    const violations = {};
    for (const log of logs) {
      if (log.type === 'POLICY_VIOLATION' && log.policy) {
        const key = log.policy.name || log.policy.id;
        violations[key] = (violations[key] || 0) + 1;
      }
      if (log.type === 'INPUT_VALIDATION_FAILED' && log.violations) {
        for (const v of log.violations) {
          violations[v.type] = (violations[v.type] || 0) + 1;
        }
      }
    }

    return Object.entries(violations)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([name, count]) => ({ name, count }));
  }
}

export default AuditLogger;
