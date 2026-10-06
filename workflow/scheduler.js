'use strict';
/** Bounded two-class scheduler used only for specialist jobs. */
const { JOB_STATE } = require('./tooling');

class ResourceScheduler {
  constructor({ maxHeavy = 1, maxLight = 2, now = () => new Date().toISOString() } = {}) {
    if (!Number.isInteger(maxHeavy) || maxHeavy < 1) throw new Error('maxHeavy must be a positive integer');
    if (!Number.isInteger(maxLight) || maxLight < 1) throw new Error('maxLight must be a positive integer');
    this.limits = { HEAVY: maxHeavy, LIGHT: maxLight };
    this.active = { HEAVY: 0, LIGHT: 0 };
    this.queue = [];
    this.jobs = new Map();
    this.now = now;
  }

  add({ id, resourceClass = 'LIGHT', run }) {
    if (!id || this.jobs.has(id)) throw new Error(`duplicate or empty job id: ${id}`);
    if (!['HEAVY', 'LIGHT'].includes(resourceClass)) throw new Error(`invalid resource class: ${resourceClass}`);
    if (typeof run !== 'function') throw new Error('job.run must be a function');
    const controller = new AbortController();
    let settle;
    const promise = new Promise((resolve) => { settle = resolve; });
    const job = { id, resourceClass, run, controller, state: JOB_STATE.QUEUED, queuedAt: this.now(), startedAt: null, finishedAt: null, durationMs: null, result: null, settle, promise };
    this.jobs.set(id, job);
    this.queue.push(job);
    this.pump();
    return job;
  }

  cancel(id) {
    const job = this.jobs.get(id);
    if (!job) return false;
    if (job.state === JOB_STATE.QUEUED) {
      job.state = JOB_STATE.CANCELLED;
      job.finishedAt = this.now();
      job.durationMs = 0;
      job.result = { state: JOB_STATE.CANCELLED, cancelled: true };
      this.queue = this.queue.filter((item) => item !== job);
      job.settle(job);
      return true;
    }
    if (job.state === JOB_STATE.RUNNING) { job.controller.abort(); return true; }
    return false;
  }

  pump() {
    for (const resourceClass of ['HEAVY', 'LIGHT']) {
      while (this.active[resourceClass] < this.limits[resourceClass]) {
        const index = this.queue.findIndex((job) => job.resourceClass === resourceClass && job.state === JOB_STATE.QUEUED);
        if (index < 0) break;
        const job = this.queue.splice(index, 1)[0];
        this.start(job);
      }
    }
  }

  start(job) {
    job.state = JOB_STATE.RUNNING;
    job.startedAt = this.now();
    const started = Date.now();
    this.active[job.resourceClass]++;
    Promise.resolve()
      .then(() => job.run({ signal: job.controller.signal, queuedAt: job.queuedAt, startedAt: job.startedAt }))
      .then((result) => {
        job.result = result || {};
        job.state = job.result.state || (job.result.ok === false ? JOB_STATE.FAILED : JOB_STATE.SUCCEEDED);
      })
      .catch((error) => {
        job.result = { state: JOB_STATE.FAILED, error: String(error && error.message || error) };
        job.state = JOB_STATE.FAILED;
      })
      .finally(() => {
        job.finishedAt = this.now();
        job.durationMs = Date.now() - started;
        this.active[job.resourceClass]--;
        job.settle(job);
        this.pump();
      });
  }

  async drain() {
    await Promise.all([...this.jobs.values()].map((job) => job.promise));
    return [...this.jobs.values()];
  }

  snapshot() {
    return [...this.jobs.values()].map((job) => ({
      id: job.id, state: job.state, resourceClass: job.resourceClass, queuedAt: job.queuedAt,
      startedAt: job.startedAt, finishedAt: job.finishedAt, durationMs: job.durationMs,
    }));
  }
}

module.exports = { ResourceScheduler };
