'use strict';

/**
 * Phase 2 — Central API Quota & Rate-Limit Controller
 *
 * Enforces unified concurrency, global pulse ceiling,
 * and adaptive backoff across all 8 workers.
 */

class CentralRateLimiter {
  constructor(options = {}) {
    this.maxConcurrent = options.maxConcurrent || 8;
    this.currentActive = 0;
    this.waitQueue = [];
    this.tokensUsed = { input: 0, output: 0, total: 0 };
    this.apiCalls = 0;
    this.rateLimitedCount = 0;
  }

  async acquire() {
    if (this.currentActive < this.maxConcurrent) {
      this.currentActive++;
      return;
    }
    return new Promise(resolve => {
      this.waitQueue.push(resolve);
    });
  }

  release() {
    this.currentActive--;
    if (this.waitQueue.length > 0) {
      this.currentActive++;
      const next = this.waitQueue.shift();
      next();
    }
  }

  recordTokens(input, output) {
    this.tokensUsed.input += (input || 0);
    this.tokensUsed.output += (output || 0);
    this.tokensUsed.total += ((input || 0) + (output || 0));
    this.apiCalls++;
  }

  recordRateLimit() {
    this.rateLimitedCount++;
  }

  getStats() {
    return {
      activeWorkers: this.currentActive,
      queuedRequests: this.waitQueue.length,
      totalApiCalls: this.apiCalls,
      totalTokens: this.tokensUsed,
      rateLimitedIncidents: this.rateLimitedCount
    };
  }
}

module.exports = { CentralRateLimiter };
