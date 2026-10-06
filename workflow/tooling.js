'use strict';
/**
 * Specialist discovery and execution boundary.
 *
 * Preflight is intentionally filesystem-only.  In particular it never calls
 * `tool --version`: on guarded Windows hosts that would turn a legitimate
 * unavailable tool into a false failed scan.  Version probing happens only in
 * a scheduled specialist job.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { expand } = require('../lib/core');

const AVAILABILITY = Object.freeze({ AVAILABLE: 'AVAILABLE', UNAVAILABLE: 'UNAVAILABLE', INVALID: 'INVALID' });
const JOB_STATE = Object.freeze({ QUEUED: 'QUEUED', RUNNING: 'RUNNING', SUCCEEDED: 'SUCCEEDED', FAILED: 'FAILED', TIMEOUT: 'TIMEOUT', CANCELLED: 'CANCELLED', UNAVAILABLE: 'UNAVAILABLE' });

const isGuarded = (env = process.env) => /runtime-guard\.js/i.test(String(env.NODE_OPTIONS || ''))
  || String(env.SENTINEL_AUDIT_RUNTIME_GUARD || '') === '1'
  // `node --require=...` does not always place the preload into NODE_OPTIONS.
  // The require cache is the reliable in-process indication used by the guard.
  || Object.keys(require.cache || {}).some((file) => /runtime-guard\.js$/i.test(file));
const envNameFor = (tool) => `SPECIALIST_${String(tool).toUpperCase().replace(/[^A-Z0-9]/g, '_')}_PATH`;
const pathLike = (value) => /[\\/]/.test(String(value || '')) || /^[A-Za-z]:/.test(String(value || ''));

function safeEnvironment(extra = {}) {
  const out = {};
  for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT', 'PATH', 'TEMP', 'TMP', 'LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'HOME', 'NUMBER_OF_PROCESSORS', 'NODE_OPTIONS']) {
    if (process.env[key] != null) out[key] = process.env[key];
  }
  return Object.assign(out, {
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_LFS_SKIP_SMUDGE: '1',
    NO_PROXY: '*',
  }, extra);
}

function findOnPath(value, env = process.env) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  if (pathLike(raw)) return fs.existsSync(raw) && fs.statSync(raw).isFile() ? path.resolve(raw) : null;
  const extensions = path.extname(raw)
    ? ['']
    : [...new Set(['', ...String(env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean).map((x) => x.toLowerCase())])];
  for (const directory of String(env.PATH || '').split(path.delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = path.join(directory.replace(/^"|"$/g, ''), raw + extension);
      try { if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return path.resolve(candidate); } catch (_) {}
    }
  }
  return null;
}

function resolveTool(name, toolConfig = {}, opts = {}) {
  const envName = toolConfig.envVar || envNameFor(name);
  const candidates = [];
  const add = (value, source, explicit) => {
    if (value != null && String(value).trim()) candidates.push({ value: String(value), source, explicit: !!explicit });
  };
  add(opts.overrides && opts.overrides[name], 'override', true);
  add(process.env[envName], `environment:${envName}`, true);
  add(toolConfig.path, 'config.path', true);
  add(toolConfig.bin, 'config.bin', pathLike(toolConfig.bin));
  if (!candidates.length) return { name, state: AVAILABILITY.UNAVAILABLE, available: false, reason: 'no executable configured', path: null, envName, attempted: [] };

  const attempted = [];
  for (const candidate of candidates) {
    const expanded = expand(candidate.value);
    const resolved = findOnPath(expanded);
    attempted.push({ source: candidate.source, value: expanded, resolved });
    if (!resolved) continue;
    let stat;
    try { stat = fs.statSync(resolved); } catch (_) { continue; }
    if (!stat.isFile()) return { name, state: AVAILABILITY.INVALID, available: false, reason: 'configured executable is not a file', path: resolved, envName, source: candidate.source, attempted };
    const extension = path.extname(resolved).toLowerCase();
    if (isGuarded() && ['.exe', '.com'].includes(extension)) {
      return { name, state: AVAILABILITY.UNAVAILABLE, available: false, reason: 'host runtime guard prohibits direct native executable launch', path: resolved, envName, source: candidate.source, attempted, blockedByHost: true };
    }
    return { name, state: AVAILABILITY.AVAILABLE, available: true, reason: null, path: resolved, envName, source: candidate.source, attempted, version: null, versionState: 'NOT_PROBED' };
  }
  const explicit = candidates.some((item) => item.explicit);
  return {
    name,
    state: explicit ? AVAILABILITY.INVALID : AVAILABILITY.UNAVAILABLE,
    available: false,
    reason: explicit ? 'configured executable path was not found' : 'executable was not found on PATH',
    path: null,
    envName,
    attempted,
  };
}

function redact(text) {
  return String(text == null ? '' : text)
    .replace(/(gh[pousr]_[A-Za-z0-9_]{12,})/g, '[REDACTED_TOKEN]')
    .replace(/((?:api[_-]?key|secret|token|password)\s*[=:]\s*)[^\s,'"`]{6,}/gi, '$1[REDACTED]')
    .replace(/AKIA[0-9A-Z]{16}/g, '[REDACTED_AWS_KEY]')
    .replace(/(-----BEGIN [A-Z ]+ PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]+ PRIVATE KEY-----)/g, '$1\n[REDACTED]\n$2');
}

function redactValue(value) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === 'object') {
    const copy = {};
    for (const [key, child] of Object.entries(value)) copy[key] = /(?:secret|token|password|credential|private.?key)/i.test(key) ? '[REDACTED]' : redactValue(child);
    return copy;
  }
  return value;
}

/**
 * Starts a process without shell interpolation.  It records every termination
 * step so callers can prove that a timeout did not leave a child process alive.
 */
function executeProcess(command, args = [], opts = {}) {
  const queuedAt = opts.queuedAt || null;
  const startedAt = new Date().toISOString();
  const start = Date.now();
  const timeoutMs = Number.isInteger(opts.timeoutMs) && opts.timeoutMs > 0 ? opts.timeoutMs : 0;
  const graceMs = Number.isInteger(opts.graceMs) && opts.graceMs >= 0 ? opts.graceMs : 1500;
  return new Promise((resolve) => {
    let child = null;
    let settled = false;
    let spawnError = null;
    let timedOut = false;
    let cancelled = false;
    let terminationRequested = false;
    let terminationConfirmed = false;
    let forceKilled = false;
    let timeoutHandle = null;
    let forceHandle = null;
    const stdout = [];
    const stderr = [];
    const finish = (code = null, signal = null) => {
      if (settled) return;
      settled = true;
      if (timeoutHandle) clearTimeout(timeoutHandle);
      if (forceHandle) clearTimeout(forceHandle);
      const error = spawnError ? redact(spawnError.message || spawnError) : null;
      const unavailable = /RUNTIME-GUARD|BLOCKED \(EXE\)|ENOENT|not found/i.test(error || '');
      const state = timedOut ? JOB_STATE.TIMEOUT
        : cancelled ? JOB_STATE.CANCELLED
          : unavailable ? JOB_STATE.UNAVAILABLE
            : code === 0 ? JOB_STATE.SUCCEEDED : JOB_STATE.FAILED;
      resolve({
        ok: state === JOB_STATE.SUCCEEDED,
        state,
        status: code,
        signal,
        stdout: redact(Buffer.concat(stdout).toString('utf8')),
        stderr: redact(Buffer.concat(stderr).toString('utf8')),
        error,
        queuedAt,
        startedAt,
        finishedAt: new Date().toISOString(),
        durationMs: Date.now() - start,
        timeoutMs: timeoutMs || null,
        terminationRequested,
        terminationConfirmed,
        forceKilled,
        timedOut,
        cancelled,
        unavailable,
      });
    };
    const stop = (kind) => {
      if (settled || !child) return;
      if (kind === 'timeout') timedOut = true;
      if (kind === 'cancelled') cancelled = true;
      terminationRequested = true;
      try { child.kill('SIGTERM'); } catch (error) { spawnError = spawnError || error; }
      forceHandle = setTimeout(() => {
        if (settled || !child) return;
        forceKilled = true;
        try { child.kill('SIGKILL'); } catch (error) { spawnError = spawnError || error; }
      }, graceMs);
    };
    try {
      child = spawn(command, args.map(String), { cwd: opts.cwd, env: safeEnvironment(opts.env), shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (error) {
      spawnError = error;
      finish();
      return;
    }
    child.stdout && child.stdout.on('data', (data) => stdout.push(Buffer.from(data)));
    child.stderr && child.stderr.on('data', (data) => stderr.push(Buffer.from(data)));
    child.once('error', (error) => { spawnError = error; });
    child.once('close', (code, signal) => {
      if (terminationRequested) terminationConfirmed = true;
      finish(code, signal);
    });
    if (timeoutMs) timeoutHandle = setTimeout(() => stop('timeout'), timeoutMs);
    if (opts.signal) {
      if (opts.signal.aborted) stop('cancelled');
      else opts.signal.addEventListener('abort', () => stop('cancelled'), { once: true });
    }
  });
}

/**
 * Read a version out of a probe's output.  Tools often print their version and
 * still exit non-zero for unrelated reasons: semgrep writes an upgrade notice to
 * stderr and can return non-zero while stdout already says "1.175.0".  Trusting
 * only the exit code turns that noise into a working tool reported as INVALID,
 * which silently removes it from the audit.
 */
function parseVersionOutput(stdout, stderr) {
  for (const stream of [stdout, stderr]) {
    const text = String(stream || '');
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/\b\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?\b/);
      if (match) return match[0];
    }
  }
  return null;
}

async function probeVersion(resolution, opts = {}) {
  if (!resolution || resolution.state !== AVAILABILITY.AVAILABLE) return { ...resolution, version: null, versionState: 'NOT_AVAILABLE' };
  // A version probe is cheap next to a scan, but a Python launcher can still
  // take tens of seconds while a 4GB CodeQL analysis saturates the host.  One
  // retry is allowed because reporting a working tool as UNAVAILABLE silently
  // removes it from the audit and that is a worse failure than a slow probe.
  const attempts = Number.isInteger(opts.attempts) && opts.attempts > 0 ? opts.attempts : 2;
  const budget = Math.max(5000, opts.timeoutMs || 15000);
  const anomalies = [];
  let last = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const probe = await executeProcess(resolution.path, ['--version'], { timeoutMs: budget * attempt, signal: opts.signal });
    last = probe;
    if (probe.state === JOB_STATE.UNAVAILABLE) return { ...resolution, state: AVAILABILITY.UNAVAILABLE, available: false, reason: probe.error || 'host prevented version probe', version: null, versionState: 'UNAVAILABLE' };
    if (probe.cancelled) return { ...resolution, state: AVAILABILITY.UNAVAILABLE, available: false, reason: 'version probe was cancelled', version: null, versionState: 'CANCELLED' };
    if (probe.timedOut) { anomalies.push(`version probe attempt ${attempt} timed out after ${budget * attempt}ms`); continue; }
    const version = parseVersionOutput(probe.stdout, probe.stderr);
    if (version) {
      if (!probe.ok) anomalies.push(`probe exited ${probe.status == null ? 'non-zero' : probe.status} but reported version ${version}`);
      if (probe.stderr && String(probe.stderr).trim()) anomalies.push(`probe stderr: ${String(probe.stderr).trim().slice(0, 200)}`);
      return { ...resolution, version, versionState: 'PROBED', probeAnomalies: anomalies };
    }
    if (!probe.ok) {
      anomalies.push(`version probe attempt ${attempt} failed (exit ${probe.status == null ? 'n/a' : probe.status}): ${probe.error || probe.stderr || 'no output'}`);
      continue;
    }
    return { ...resolution, version: 'unknown', versionState: 'PROBED_NO_VERSION', probeAnomalies: anomalies };
  }
  return {
    ...resolution,
    state: AVAILABILITY.UNAVAILABLE,
    available: false,
    reason: `version probe did not complete after ${attempts} attempt(s): ${anomalies.join('; ')}`,
    version: null,
    versionState: 'TIMEOUT',
  };
}

function hashFile(file) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); } catch (_) { return null; }
}

function validateAuditConfig({ tools, policies }) {
  const errors = [];
  for (const tool of ['codeql', 'semgrep', 'trivy', 'osv']) if (!tools[tool] || (!tools[tool].bin && !tools[tool].path)) errors.push(`tools.${tool}.bin is missing`);
  if (!tools.sentinelCloud || !tools.sentinelCloud.engine) errors.push('tools.sentinelCloud.engine is missing');
  const supported = policies.routing && policies.routing.supportedModes;
  if (!Array.isArray(supported) || !['file', 'directory', 'repo'].every((mode) => supported.includes(mode))) errors.push('routing must support file, directory, repo');
  if (!supported || !supported.includes(policies.routing.defaultMode)) errors.push('routing.defaultMode is invalid');
  const resources = policies.resources || {};
  for (const key of ['maxHeavy', 'maxLight']) if (!Number.isInteger(resources[key]) || resources[key] < 1) errors.push(`resources.${key} must be a positive integer`);
  return { valid: errors.length === 0, errors };
}

module.exports = {
  AVAILABILITY, JOB_STATE, isGuarded, safeEnvironment, envNameFor, findOnPath, resolveTool,
  redact, redactValue, executeProcess, probeVersion, hashFile, validateAuditConfig, parseVersionOutput,
};
