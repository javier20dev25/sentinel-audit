'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const zlib = require('node:zlib');
const { runHostedCloud } = require('../adapters/hosted');
const { runSentinelCloud } = require('../adapters');
const { STATUS, loadConfig } = require('../lib/core');

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function write(root, rel, content) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

function repo() {
  const root = tempDir('sentinel-audit-hosted-repo-');
  write(root, 'app.js', 'const x = 1;\n');
  return root;
}

function makeCtx(work, overrides = {}) {
  return Object.assign({
    work,
    tools: { sentinelCloud: { hosted: { clientModule: '@sentinel/cloud-client', fallbackClientPath: '__unused__' } } },
    policies: { hosted: { enabled: true, provider: 'sentinel-cloud', pollIntervalMs: 1, waitTimeoutMs: 1000, maxFiles: 1000, maxFileBytes: 1048576, maxArchiveBytes: 26214400 } },
    pre: { name: 'fixture', commit: 'a'.repeat(40), trackedFiles: ['app.js'], health: { sentinel: { engineId: 'engine@rev' } } },
    provider: 'cloud',
  }, overrides);
}

const SIGNAL = { type: 'SECRET_LEAK', path: 'app.js', lineNumber: 4, title: 'secret', message: 'found' };

function envelopeWith(overrides = {}) {
  return Object.assign({
    engine: { hash: 'engine-hash' },
    executionComplete: true, coverageKnown: true, coverageUnknown: false,
    filesScanned: 3, filesFailed: 0, alertsSeen: 1, alertsEnrichFailed: 0,
    signals: [SIGNAL],
  }, overrides);
}

function fakeClient(handlers = {}) {
  return Object.assign({
    getResolvedBaseUrl: (flag) => flag || 'https://cloud.example',
    resolveToken: (flag) => flag || 'SECRET-TOKEN',
    submitRepositoryScan: async () => ({ ok: true, data: { scanId: 'scan-1', status: 'PENDING' } }),
    waitForRepositoryScan: async () => ({ ok: true, envelope: envelopeWith() }),
  }, handlers);
}

test('a healthy hosted scan produces the standard envelope and a hosted raw artifact', async () => {
  const root = repo();
  write(root, 'ignored.js', 'not tracked');
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-work-'));
  let submitted;
  const client = fakeClient({
    // Copy: the provider wipes the in-memory buffer right after submit, and the
    // test asserts both the packed contents and that the wipe happened.
    submitRepositoryScan: async (bytes) => { submitted = Buffer.from(bytes); return { ok: true, data: { scanId: 'scan-1', status: 'PENDING' } }; },
  });
  const env = await runHostedCloud(root, ctx, { cloudClient: client });

  assert.equal(env.tool, 'sentinel');
  assert.equal(env.status, STATUS.SUCCESS);
  assert.equal(env.findings.length, 1);
  assert.equal(env.findings[0].category, 'secret');
  assert.equal(env.findings[0].file, path.join(root, 'app.js'));
  assert.equal(env.findings[0].line, 4);
  assert.equal(env.signalCounts.actionable, 1);
  assert.equal(env.coverage.engineExecutionComplete, true);
  assert.equal(env.coverage.coverageKnown, true);

  // Only the git-tracked file is packed; the untracked one never leaves the host.
  const tar = zlib.gunzipSync(submitted).toString('latin1');
  assert.ok(tar.includes('app.js'));
  assert.ok(!tar.includes('ignored.js'));

  const raw = JSON.parse(fs.readFileSync(env.rawArtifact, 'utf8'));
  assert.equal(raw.mode, 'hosted');
  assert.equal(raw.scanId, 'scan-1');
  assert.ok(!JSON.stringify(raw).includes('SECRET-TOKEN'));
  assert.ok(!JSON.stringify(env).includes('SECRET-TOKEN'));
});

test('the source archive buffer is wiped after submit', async () => {
  const root = repo();
  let live;
  const client = fakeClient({ submitRepositoryScan: async (bytes) => { live = bytes; return { ok: true, data: { scanId: 's', status: 'PENDING' } }; } });
  await runHostedCloud(root, makeCtx(tempDir('sentinel-audit-hosted-wipe-')), { cloudClient: client });
  assert.ok(live && live.length > 0);
  assert.ok(live.every((byte) => byte === 0), 'packed bytes must be zeroed after the archive leaves the process');
});

test('reported coverage without completeness degrades to PARTIAL', async () => {
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-work-'));
  const client = fakeClient({ waitForRepositoryScan: async () => ({ ok: true, envelope: envelopeWith({ coverageKnown: false, coverageUnknown: true }) }) });
  const env = await runHostedCloud(repo(), ctx, { cloudClient: client });
  assert.equal(env.status, STATUS.PARTIAL);
  assert.equal(env.coverage.engineCoverage, 'ENGINE_COVERAGE_UNMEASURED');
});

test('an incomplete engine execution is an ERROR, never a clean scan', async () => {
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-work-'));
  const client = fakeClient({ waitForRepositoryScan: async () => ({ ok: true, envelope: envelopeWith({ executionComplete: false, signals: [] }) }) });
  const env = await runHostedCloud(repo(), ctx, { cloudClient: client });
  assert.equal(env.status, STATUS.ERROR);
  assert.equal(env.coverage.engineIncomplete, true);
});

test('unauthorized submission maps to ERROR and never leaks the token', async () => {
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-work-'));
  const client = fakeClient({ submitRepositoryScan: async () => ({ ok: false, code: 'UNAUTHORIZED', error: 'rejected token SECRET-TOKEN', retryable: false }) });
  const env = await runHostedCloud(repo(), ctx, { cloudClient: client });
  assert.equal(env.status, STATUS.ERROR);
  assert.match(env.error, /UNAUTHORIZED/);
  assert.ok(!env.error.includes('SECRET-TOKEN'));
  assert.ok(!JSON.stringify(env).includes('SECRET-TOKEN'));
});

test('quota exhaustion and rate limiting keep their retry semantics', async () => {
  const quotaCtx = makeCtx(tempDir('sentinel-audit-hosted-quota-'));
  const quota = await runHostedCloud(repo(), quotaCtx, {
    cloudClient: fakeClient({ submitRepositoryScan: async () => ({ ok: false, code: 'QUOTA_EXHAUSTED', error: 'plan quota exhausted', retryable: false }) }),
  });
  assert.match(quota.error, /QUOTA_EXHAUSTED/);
  assert.ok(quota.notes.some((note) => note === 'retryable=false'));

  const rateCtx = makeCtx(tempDir('sentinel-audit-hosted-rate-'));
  const rate = await runHostedCloud(repo(), rateCtx, {
    cloudClient: fakeClient({ submitRepositoryScan: async () => ({ ok: false, code: 'RATE_LIMITED', error: 'slow down', retryable: true }) }),
  });
  assert.match(rate.error, /RATE_LIMITED/);
  assert.ok(rate.notes.some((note) => note === 'retryable=true'));
});

test('a failed job after submission persists failure evidence', async () => {
  const work = tempDir('sentinel-audit-hosted-failed-');
  const ctx = makeCtx(work);
  const env = await runHostedCloud(repo(), ctx, {
    cloudClient: fakeClient({ waitForRepositoryScan: async () => ({ ok: false, code: 'SERVER_ERROR', scanStatus: 'FAILED', error: 'worker crashed', retryable: false }) }),
  });
  assert.equal(env.status, STATUS.ERROR);
  assert.match(env.error, /FAILED/);
  assert.ok(fs.existsSync(path.join(work, 'cloud', 'hosted-error.json')));
});

test('a poll timeout and a cancellation both surface as ERROR with their status', async () => {
  const timeout = await runHostedCloud(repo(), makeCtx(tempDir('sentinel-audit-hosted-to-')), {
    cloudClient: fakeClient({ waitForRepositoryScan: async () => ({ ok: false, code: 'UNAVAILABLE', scanStatus: 'PROCESSING', error: 'wait deadline exceeded', retryable: true }) }),
  });
  assert.equal(timeout.status, STATUS.ERROR);
  assert.match(timeout.error, /PROCESSING/);

  const cancelled = await runHostedCloud(repo(), makeCtx(tempDir('sentinel-audit-hosted-cancel-')), {
    cloudClient: fakeClient({ waitForRepositoryScan: async () => ({ ok: false, code: 'UNAVAILABLE', scanStatus: 'CANCELLED', error: 'scan cancelled', retryable: false }) }),
  });
  assert.equal(cancelled.status, STATUS.ERROR);
  assert.match(cancelled.error, /CANCELLED/);
});

test('missing or malformed result signals do not throw', async () => {
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-malformed-'));
  const client = fakeClient({ waitForRepositoryScan: async () => ({ ok: true, envelope: envelopeWith({ coverageKnown: false, signals: [null, 7, 'bad', { type: 'X' }] }) }) });
  const env = await runHostedCloud(repo(), ctx, { cloudClient: client });
  assert.equal(env.findings.length, 4);
  assert.ok(env.findings.every((finding) => typeof finding.signalId === 'string'));
});

test('an aborted run never submits the archive', async () => {
  let submitted = false;
  const client = fakeClient({ submitRepositoryScan: async () => { submitted = true; return { ok: true, data: { scanId: 's', status: 'PENDING' } }; } });
  const controller = new AbortController();
  controller.abort();
  const env = await runHostedCloud(repo(), makeCtx(tempDir('sentinel-audit-hosted-abort-')), { cloudClient: client, signal: controller.signal });
  assert.equal(env.status, STATUS.ERROR);
  assert.equal(submitted, false);
});

test('a client without the protocol surface fails closed as UNAVAILABLE', async () => {
  const env = await runHostedCloud(repo(), makeCtx(tempDir('sentinel-audit-hosted-noclient-')), { cloudClient: {} });
  assert.equal(env.status, STATUS.ERROR);
  assert.match(env.error, /UNAVAILABLE/);
});

test('a missing token fails closed before packing or submitting', async () => {
  let submitted = false;
  const client = fakeClient({ resolveToken: () => null, submitRepositoryScan: async () => { submitted = true; return { ok: true, data: {} }; } });
  const env = await runHostedCloud(repo(), makeCtx(tempDir('sentinel-audit-hosted-notoken-')), { cloudClient: client });
  assert.equal(env.status, STATUS.ERROR);
  assert.match(env.error, /UNAUTHORIZED/);
  assert.equal(submitted, false);
});

test('an unusable base URL fails closed as INVALID_REQUEST', async () => {
  const client = fakeClient({ getResolvedBaseUrl: () => { throw new Error('insecure base url'); } });
  const env = await runHostedCloud(repo(), makeCtx(tempDir('sentinel-audit-hosted-badurl-')), { cloudClient: client });
  assert.equal(env.status, STATUS.ERROR);
  assert.match(env.error, /INVALID_REQUEST/);
});

test('an archive over the configured cap fails closed before submitting', async () => {
  let submitted = false;
  const client = fakeClient({ submitRepositoryScan: async () => { submitted = true; return { ok: true, data: {} }; } });
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-cap-'));
  ctx.policies.hosted.maxArchiveBytes = 1;
  const env = await runHostedCloud(repo(), ctx, { cloudClient: client });
  assert.equal(env.status, STATUS.ERROR);
  assert.match(env.error, /INVALID_REQUEST/);
  assert.equal(submitted, false);
});

test('server-side rejections surface as ERROR envelopes, never a throw', async () => {
  const cases = [
    ['INVALID_REQUEST', 'archive is not a valid gzip stream'],
    ['UNAVAILABLE', 'cloud worker did not answer'],
    ['SERVER_ERROR', 'internal error'],
  ];
  for (const [code, message] of cases) {
    const ctx = makeCtx(tempDir('sentinel-audit-hosted-reject-'));
    const env = await runHostedCloud(repo(), ctx, { cloudClient: fakeClient({ submitRepositoryScan: async () => ({ ok: false, code, error: message, retryable: false }) }) });
    assert.equal(env.status, STATUS.ERROR);
    assert.match(env.error, new RegExp(code));
  }
});

test('a result missing its signal list is treated as zero signals, not a crash', async () => {
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-empty-'));
  const client = fakeClient({ waitForRepositoryScan: async () => ({ ok: true, envelope: { executionComplete: true, coverageKnown: true } }) });
  const env = await runHostedCloud(repo(), ctx, { cloudClient: client });
  assert.equal(env.status, STATUS.SUCCESS);
  assert.equal(env.findings.length, 0);
  assert.equal(env.coverage.filesScanned, null);
});

test('a network drop while polling is a retryable ERROR', async () => {
  const ctx = makeCtx(tempDir('sentinel-audit-hosted-drop-'));
  const env = await runHostedCloud(repo(), ctx, {
    cloudClient: fakeClient({ waitForRepositoryScan: async () => ({ ok: false, code: 'UNAVAILABLE', error: 'socket hang up', retryable: true }) }),
  });
  assert.equal(env.status, STATUS.ERROR);
  assert.ok(env.notes.some((note) => note === 'retryable=true'));
});

test('aborting during polling surfaces as ERROR without submitting again', async () => {
  let submitCount = 0;
  const controller = new AbortController();
  const client = fakeClient({
    submitRepositoryScan: async () => { submitCount += 1; return { ok: true, data: { scanId: 's', status: 'PENDING' } }; },
    waitForRepositoryScan: async (_id, _token, _base, opts) => {
      controller.abort();
      return opts.signal && opts.signal.aborted
        ? { ok: false, code: 'UNAVAILABLE', scanStatus: 'PROCESSING', error: 'aborted during polling', retryable: true }
        : { ok: true, envelope: envelopeWith() };
    },
  });
  const env = await runHostedCloud(repo(), makeCtx(tempDir('sentinel-audit-hosted-abortpoll-')), { cloudClient: client, signal: controller.signal });
  assert.equal(env.status, STATUS.ERROR);
  assert.equal(submitCount, 1);
});

test('checkHostedHealth lists every missing prerequisite without touching the network', () => {
  const { checkHostedHealth } = require('../workflow/preflight');
  const { tools, policies } = loadConfig();
  const disabled = checkHostedHealth(tools, policies, {}, {});
  assert.equal(disabled.enabled, false);
  assert.ok(disabled.reasons.some((reason) => /disabled by policy/.test(reason)));
  assert.ok(disabled.reasons.some((reason) => /base URL/.test(reason)));
  assert.ok(disabled.reasons.some((reason) => /API token/.test(reason)));

  const enabled = checkHostedHealth(tools, { hosted: { enabled: true } }, { apiUrl: 'https://cloud.example' }, { SENTINEL_CLOUD_API_TOKEN: 'x' });
  assert.equal(enabled.reasons.length, 0);
  assert.equal(enabled.tokenPresent, true);
});

test('local and hosted providers emit the same envelope key set and finding shape', async () => {
  const root = repo();
  const rawResult = { rawAlerts: [Object.assign({}, SIGNAL, { file: 'app.js', line: 4 })], filesScanned: 3, filesScanFailed: 0, alertsEnrichFailed: 0, degradationSamples: [] };
  const localCtx = makeCtx(tempDir('sentinel-audit-parity-local-'), { tools: { sentinelCloud: { engine: 'unused' } } });
  const local = await runSentinelCloud(root, localCtx, () => ({ scanDirectory: async () => rawResult }), path.join('C:', 'fake', 'engine.js'));

  const hostedCtx = makeCtx(tempDir('sentinel-audit-parity-hosted-'));
  const hosted = await runHostedCloud(root, hostedCtx, { cloudClient: fakeClient({ waitForRepositoryScan: async () => ({ ok: true, envelope: envelopeWith({ coverageKnown: false }) }) }) });

  assert.deepEqual(Object.keys(local).sort(), Object.keys(hosted).sort());
  assert.deepEqual(Object.keys(local.coverage).sort(), Object.keys(hosted.coverage).sort());
  const shape = (finding) => ({ signalId: finding.signalId, tool: finding.tool, rule: finding.rule, kind: finding.kind, category: finding.category, file: finding.file, line: finding.line, detail: finding.detail, signalClass: finding.signalClass });
  assert.deepEqual(shape(local.findings[0]), shape(hosted.findings[0]));
});
