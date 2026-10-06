'use strict';
/**
 * Hosted Cloud provider (P0-9).
 *
 * Unlike the local adapter, which reaches into the private worker engine through
 * a bridge, this provider never touches detection logic.  It is deliberately
 * thin: pack the pinned checkout, hand the archive to @sentinel/cloud-client
 * (which owns every byte of protocol, auth and transport), poll, and translate
 * the server's public envelope into the same audit envelope the local provider
 * emits.  All downstream stages (routing, specialists, correlation, report) are
 * identical for both providers, so "hosted and local" are the same pipeline with
 * a different source of Cloud signals.
 *
 * Hard rules enforced here:
 *   - No HTTP, no auth, no URL construction: that is the client's job.
 *   - The bearer token is never written to an artifact, a note or an error.
 *   - The source archive is built in memory and wiped after submit; it is never
 *     retained on disk.
 *   - Every failure becomes an ERROR envelope.  It never throws into the
 *     pipeline and never turns an outage into a clean scan.
 */
const fs = require('fs');
const path = require('path');
const { STATUS, envelope, expand } = require('../lib/core');
const { writeJson } = require('../workflow/artifacts');
const { redactValue } = require('../workflow/tooling');
const { packRepository, ARCHIVE_MAX_BYTES } = require('../workflow/archive');
const { normalizeCloudSignals } = require('./normalize');

/** Resolves the cloud client without assuming an install layout. */
function resolveClient(ctx, opts) {
  if (opts.cloudClient) return opts.cloudClient;
  const hosted = (ctx.tools && ctx.tools.sentinelCloud && ctx.tools.sentinelCloud.hosted) || {};
  const candidates = [];
  if (hosted.clientModule) candidates.push(hosted.clientModule);
  candidates.push('@sentinel/cloud-client');
  // fallbackClientPath allows development checkouts without npm install.
  // Set SENTINEL_CLOUD_CLIENT_PATH env var or hosted.fallbackClientPath in config.
  if (hosted.fallbackClientPath) candidates.push(expand(hosted.fallbackClientPath));
  const envFallback = process.env.SENTINEL_CLOUD_CLIENT_PATH;
  if (envFallback) candidates.push(envFallback);
  for (const candidate of candidates) {
    try { return require(candidate); } catch (_) { /* try the next resolution path */ }
  }
  return null;
}

function collectFiles(root, ctx, opts) {
  if (opts.files) return opts.files;
  if (ctx.pre && Array.isArray(ctx.pre.trackedFiles)) return ctx.pre.trackedFiles;
  const { walkFiles } = require('../workflow/archive');
  return walkFiles(root);
}

function scrub(token, text) {
  const value = String(text == null ? '' : text);
  return token ? value.split(token).join('[redacted]') : value;
}

function failure(startedAt, code, message, extra = {}) {
  const detail = `hosted scan failed [${code}]${extra.scanStatus ? ` (${extra.scanStatus})` : ''}: ${message || 'no message'}`;
  return envelope('sentinel', {
    status: STATUS.ERROR,
    coverage: {
      engineExecutionComplete: false, engineIncomplete: true, coverageKnown: false, coverageUnknown: true,
      filesScanned: null, filesFailed: null, alertsSeen: null, alertsEnrichFailed: null, degradationSamples: null,
      errors: [detail],
    },
    cost: { wallClockMs: Date.now() - startedAt },
    error: detail,
    notes: [
      `hosted Cloud provider error code: ${code}`,
      `retryable=${extra.retryable === true}`,
      'no local engine was executed for this run',
    ],
  });
}

/**
 * Runs a hosted repository scan and returns the standard audit envelope.
 * Never throws: any failure is returned as an ERROR envelope so the pipeline's
 * specialist stage is unaffected by a Cloud outage.
 */
async function runHostedCloud(root, ctx, opts = {}) {
  const startedAt = Date.now();
  const rawDir = path.join(ctx.work, 'cloud');
  fs.mkdirSync(rawDir, { recursive: true });
  const rawPath = path.join(rawDir, 'raw.json');
  const policies = (ctx.policies && ctx.policies.hosted) || {};
  const hostedCfg = (ctx.tools && ctx.tools.sentinelCloud && ctx.tools.sentinelCloud.hosted) || {};

  const client = resolveClient(ctx, opts);
  if (!client || typeof client.submitRepositoryScan !== 'function' || typeof client.waitForRepositoryScan !== 'function') {
    return failure(startedAt, 'UNAVAILABLE', 'hosted Cloud client @sentinel/cloud-client is not resolvable');
  }

  if (opts.signal && opts.signal.aborted) {
    return failure(startedAt, 'UNAVAILABLE', 'hosted scan was aborted before submission', { retryable: true });
  }

  const env = process.env;
  const baseUrlEnv = hostedCfg.baseUrlEnv || 'SENTINEL_CLOUD_URL';
  const tokenEnv = hostedCfg.tokenEnv || 'SENTINEL_CLOUD_API_TOKEN';
  let baseUrl;
  try {
    baseUrl = client.getResolvedBaseUrl(opts.apiUrl || env[baseUrlEnv] || undefined, env);
  } catch (error) {
    return failure(startedAt, 'INVALID_REQUEST', scrub(null, error && error.message || error));
  }

  let token = typeof client.resolveToken === 'function' ? client.resolveToken(opts.apiToken || env[tokenEnv] || undefined, env) : null;
  if (!token && typeof client.loadSession === 'function') {
    const session = client.loadSession();
    if (session && typeof session.token === 'string') token = session.token;
  }
  if (!token) {
    return failure(startedAt, 'UNAUTHORIZED', 'no Sentinel Cloud API token is configured (SENTINEL_CLOUD_API_TOKEN or session)');
  }

  let packed;
  try {
    packed = packRepository(root, {
      files: collectFiles(root, ctx, opts),
      maxFiles: policies.maxFiles,
      maxFileBytes: policies.maxFileBytes,
      maxArchiveBytes: policies.maxArchiveBytes || ARCHIVE_MAX_BYTES,
    });
  } catch (error) {
    return failure(startedAt, 'INVALID_REQUEST', `repository archive could not be built: ${scrub(token, error && error.message || error)}`);
  }

  const submitted = await client.submitRepositoryScan(packed.bytes, token, baseUrl, {
    repoLabel: ctx.pre && ctx.pre.name,
    commitSha: ctx.pre && ctx.pre.commit,
    timeoutMs: opts.submitTimeoutMs,
  });
  // The archive has left the process; wipe the buffer so the source tree is not
  // retained in memory for the rest of the run.
  packed.bytes.fill(0);
  if (!submitted || submitted.ok !== true) {
    const code = (submitted && submitted.code) || 'UNAVAILABLE';
    return failure(startedAt, code, scrub(token, sourceMessage(submitted)), { retryable: submitted && submitted.retryable, scanStatus: submitted && submitted.scanStatus });
  }

  const scanId = submitted.data.scanId;
  const statusTransitions = [];
  const waited = await client.waitForRepositoryScan(scanId, token, baseUrl, {
    pollIntervalMs: policies.pollIntervalMs,
    waitTimeoutMs: policies.waitTimeoutMs,
    signal: opts.signal,
    onStatus: (summary) => statusTransitions.push(summary && summary.status),
  });
  if (!waited || waited.ok !== true) {
    try {
      writeJson(path.join(rawDir, 'hosted-error.json'), {
        scanId, statusTransitions,
        code: (waited && waited.code) || 'UNAVAILABLE',
        retryable: !!(waited && waited.retryable),
        error: scrub(token, (waited && waited.error) || 'hosted scan did not complete'),
      });
    } catch (_) { /* evidence is best effort on a failed scan */ }
    return failure(startedAt, (waited && waited.code) || 'UNAVAILABLE', scrub(token, sourceMessage(waited)), {
      retryable: waited && waited.retryable, scanStatus: waited && waited.scanStatus,
    });
  }

  const result = waited.envelope;
  try {
    writeJson(rawPath, {
      mode: 'hosted',
      scanId,
      engine: result.engine || null,
      submission: { scanId, status: submitted.data.status },
      statusTransitions,
      archive: {
        sha256: packed.sha256, fileCount: packed.fileCount, archiveBytes: packed.archiveBytes,
        skippedSymlinks: packed.skippedSymlinks, skippedOversized: packed.skippedOversized, skippedNonFile: packed.skippedNonFile,
      },
      result: redactValue(result),
    });
  } catch (error) {
    return failure(startedAt, 'SERVER_ERROR', `raw output persistence failed: ${scrub(token, error && error.message || error)}`);
  }

  const findings = normalizeCloudSignals(root, result.signals || []);
  const complete = result.executionComplete === true;
  const known = result.coverageKnown === true;
  // A counter the server did not send is unknown, not zero: `undefined` would
  // erase the distinction in the persisted envelope.
  const intOrNull = (value) => (Number.isInteger(value) ? value : null);
  const filesScanned = intOrNull(result.filesScanned);
  const filesFailed = intOrNull(result.filesFailed);
  const alertsSeen = intOrNull(result.alertsSeen);
  const alertsEnrichFailed = intOrNull(result.alertsEnrichFailed);
  const status = !complete ? STATUS.ERROR : known ? STATUS.SUCCESS : STATUS.PARTIAL;
  const engineVersion = (result.engine && (result.engine.hash || result.engine.revision)) || null;

  return envelope('sentinel', {
    status,
    findings,
    signalCounts: {
      total: findings.length,
      actionable: findings.filter((finding) => finding.signalClass === 'ACTIONABLE_SIGNAL').length,
      observationOnly: findings.filter((finding) => finding.signalClass !== 'ACTIONABLE_SIGNAL').length,
    },
    coverage: {
      filesSeen: null, filesEligible: null, filesParsed: null,
      analysisCompleted: complete,
      engineExecutionComplete: complete,
      engineIncomplete: !complete,
      coverageKnown: known,
      // coverageUnknown is the exact inverse of coverageKnown: only the engine
      // can claim coverage, so a missing claim is an unknown, never a healthy 0.
      coverageUnknown: !known,
      filesScanned,
      filesFailed,
      alertsSeen,
      alertsEnrichFailed,
      // Legacy alias kept so the hosted coverage key set matches the local one.
      alertsFailed: alertsEnrichFailed,
      degradationSamples: null,
      engineCoverage: known ? 'ENGINE_COVERAGE_REPORTED' : 'ENGINE_COVERAGE_UNMEASURED',
      engineFilesScannedReported: filesScanned,
      errors: [],
    },
    cost: { wallClockMs: Date.now() - startedAt },
    notes: [
      'hosted Sentinel Cloud scan; source archive packed locally and not retained',
      `scanId=${scanId} statuses=${statusTransitions.join('>') || 'none'}`,
      `archive sha256=${packed.sha256} files=${packed.fileCount} bytes=${packed.archiveBytes}`,
      packed.skippedSymlinks.length ? `symlinks skipped (never followed): ${packed.skippedSymlinks.length}` : null,
      packed.skippedOversized.length ? `oversized files skipped: ${packed.skippedOversized.length}` : null,
    ].filter(Boolean),
    rawArtifact: rawPath,
    version: engineVersion,
  });
}

/** Reads the client's own message without ever echoing the token. */
function sourceMessage(result) {
  if (result && typeof result.error === 'string' && result.error) return result.error;
  if (result && result.scanStatus) return `scan ${result.scanStatus}`;
  return 'hosted scan failed';
}

module.exports = { runHostedCloud, resolveClient, collectFiles };
