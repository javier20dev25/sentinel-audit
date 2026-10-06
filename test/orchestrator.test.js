'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { normalizeCloudSignals, runSentinelCloud } = require('../adapters');
const { buildRoutePlan } = require('../workflow/audit');
const { cleanupRun } = require('../workflow/cleanup');
const { correlate, auditVerdict, scopeOf } = require('../correlate');
const { loadConfig, STATUS, inventory } = require('../lib/core');
const { parseVersionOutput } = require('../workflow/tooling');
const { normalizeSemgrepRuleId, localSemgrepConfigs, abs, parseSarif, usableTargets } = require('../workflow/specialist-runtime');
const { rebaseTargets } = require('../workflow/workspace');
const { reasonFromStderr, osvExitSucceeded } = require('../workflow/specialist-runtime');
const { executeSpecialist } = require('../workflow/specialist-runtime');
const { abs: resolveTarget, relTarget, realContained } = require('../workflow/paths');
const { manifest, verifyManifest } = require('../workflow/artifacts');


const root = path.resolve('fixture-repo');
const routingMap = loadConfig().policies.routing.signalToolMap;

test('malformed Cloud alert values are contained during normalization', () => {
  const normalized = normalizeCloudSignals(root, [null, 7, 'bad', { type: 'CAPABILITY_CHAIN', _file: 'app.js', description: 'exec' }, { type: 'RULE', file: 17 }]);
  assert.equal(normalized.length, 5);
  assert.ok(normalized.every((x) => typeof x.signalId === 'string'));
  assert.equal(normalized[3].file, path.join(root, 'app.js'));
  assert.equal(normalized[4].file, null);
});

test('direct Cloud adapter preserves raw output before normalizing', async () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-cloud-test-'));
  const rawResult = { filesScanned: 4, filesScanFailed: 0, alertsEnrichFailed: 0, rawAlerts: [{ type: 'CAPABILITY_CHAIN', _fullPath: path.join(root, 'src.js'), line: 4, description: 'execution' }] };
  const ctx = { work, tools: { sentinelCloud: { engine: 'unused' } }, pre: { health: { sentinel: { engineId: 'test-engine' } } } };
  try {
    const envelope = await runSentinelCloud(root, ctx, () => ({ scanDirectory: () => Promise.resolve(rawResult) }), 'mock-cloud-engine');
    assert.equal(envelope.coverage.engineExecutionComplete, true);
    assert.equal(envelope.coverage.coverageUnknown, true);
    assert.equal(envelope.findings.length, 1);
    const raw = JSON.parse(fs.readFileSync(envelope.rawArtifact, 'utf8'));
    assert.deepEqual(raw.result, rawResult);
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
});

test('Cloud rejection becomes an incomplete error, not an empty scan', async () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-cloud-fail-test-'));
  const ctx = { work, tools: { sentinelCloud: { engine: 'unused' } }, pre: {} };
  try {
    const envelope = await runSentinelCloud(root, ctx, () => ({ scanDirectory: () => Promise.reject(new Error('synthetic failure')) }), 'mock-cloud-engine');
    assert.equal(envelope.status, STATUS.ERROR);
    assert.equal(envelope.coverage.engineExecutionComplete, false);
    assert.match(envelope.error, /synthetic failure/);
    assert.equal(envelope.findingCount, 0);
  } finally { fs.rmSync(work, { recursive: true, force: true }); }
});

test('routing file, directory, and repo are deterministic and explicit', () => {
  const signals = [
    { signalId: 'SIG-1', file: path.join(root, 'src', 'a.js'), category: 'process', signalClass: 'ACTIONABLE_SIGNAL' },
    { signalId: 'SIG-2', file: path.join(root, 'src', 'b.js'), category: 'secret', signalClass: 'ACTIONABLE_SIGNAL' },
  ];
  const f = buildRoutePlan(signals, STATUS.PARTIAL, 'file', root, {}, routingMap);
  const d = buildRoutePlan(signals, STATUS.PARTIAL, 'directory', root, {}, routingMap);
  const r = buildRoutePlan(signals, STATUS.PARTIAL, 'repo', root, {}, routingMap);
  assert.equal(f.targets.length, 2);
  // Routing targets are persisted as repository-relative identities: the repo root
  // is '.', never an absolute path into a disposable worktree.
  assert.deepEqual(f.targets, ['src/a.js', 'src/b.js']);
  assert.deepEqual(d.targets, ['src']);
  assert.deepEqual(r.targets, ['.']);
  assert.ok(f.targets.every((t) => !path.isAbsolute(t)), 'targets must not be absolute');
  assert.deepEqual(f.promotions.map((p) => p.target), f.targets);
  assert.deepEqual(f.tools, ['codeql', 'semgrep']);
  assert.equal(f.promotions[0].signalIds.length, 1);
  assert.equal(buildRoutePlan(signals, STATUS.PARTIAL, 'file', root, {}, routingMap).promotions[0].promotionId, f.promotions[0].promotionId);
  assert.deepEqual(buildRoutePlan(signals, STATUS.PARTIAL, 'file', root, {}, routingMap), f);
});

test('engine failure is incomplete, never routed as no-actionable', () => {
  const plan = buildRoutePlan([], STATUS.ERROR, 'file', root, {}, routingMap);
  assert.equal(plan.decision, 'SENTINEL_ENGINE_INCOMPLETE');
  assert.equal(plan.engineIncomplete, true);
  assert.deepEqual(plan.tools, []);
});

test('coverage unknown is distinct from a successful execution', () => {
  const plan = buildRoutePlan([], STATUS.PARTIAL, 'file', root, { coverageKnown: false }, routingMap);
  assert.equal(plan.decision, 'NO_ACTIONABLE_SENTINEL_FINDINGS');
  assert.equal(plan.engineIncomplete, false);
  assert.equal(plan.signalCount, 0);
});

test('unknown coverage never produces a clean claim', () => {
  const sentinel = { tool: 'sentinel', status: STATUS.PARTIAL, verdict: 'NO_SIGNALS_LIMITED_COVERAGE', findings: [], signalCounts: { actionable: 0 }, coverage: { coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED' } };
  const nonApplicable = ['codeql', 'semgrep', 'bandit', 'shellcheck'].map((tool) => ({ tool, status: STATUS.SKIPPED, verdict: 'NOT_APPLICABLE', notApplicable: true, findings: [], coverage: { analysisCompleted: true, errors: [] } }));
  const verdict = auditVerdict([sentinel, ...nonApplicable], []);
  assert.equal(verdict.verdict, 'NO_ACTIONABLE_SENTINEL_FINDINGS');
  assert.equal(verdict.canClaimClean, false);
});

test('external actions remain forbidden by default policy', () => {
  const publication = loadConfig().policies.publication;
  assert.ok(Object.entries(publication).filter(([key]) => !key.startsWith('_')).every(([, value]) => value === 'FORBIDDEN'));
});

test('cleanup removes only the run-local CodeQL database and preserves evidence', () => {
  const out = path.resolve(__dirname, '..', 'out');
  fs.mkdirSync(out, { recursive: true });
  const runDir = fs.mkdtempSync(path.join(out, 'test-cleanup-'));
  fs.mkdirSync(path.join(runDir, 'codeql-db'));
  fs.writeFileSync(path.join(runDir, 'codeql-db', 'db.bin'), 'temp');
  fs.writeFileSync(path.join(runDir, 'identity.json'), '{"keep":true}');
  try {
    const result = cleanupRun(runDir);
    assert.equal(result.cleanupStatus, 'SUCCESS');
    assert.deepEqual(result.removed, ['codeql-db']);
    assert.equal(fs.existsSync(path.join(runDir, 'identity.json')), true);
  } finally { fs.rmSync(runDir, { recursive: true, force: true }); }
});

test('candidate retains Cloud signal, route, job, specialist-finding and correlation IDs', () => {
  const cloud = { tool: 'sentinel', findings: [{ signalId: 'SIG-1', signalClass: 'ACTIONABLE_SIGNAL', file: path.join(root, 'src', 'a.js'), line: 20, detail: 'process execution', category: 'process', promotionIds: ['PROM-1'] }] };
  const semgrep = { tool: 'semgrep', findings: [{ specialistFindingId: 'SF-1', jobId: 'JOB-1', promotionIds: ['PROM-1'], file: path.join(root, 'src', 'a.js'), line: 20, endLine: 21, rule: 'exec-rule', level: 'HIGH', detail: 'rule evidence' }] };
  const out = correlate(root, [cloud, semgrep], loadConfig().policies);
  assert.equal(out.candidates.length, 1);
  const c = out.candidates[0];
  assert.equal(c.candidateStatus, 'PLAUSIBLE_SECURITY_ISSUE');
  assert.equal(c.verificationStatus, 'MANUAL_VERIFICATION_REQUIRED');
  assert.deepEqual(c.signalIds, ['SIG-1']);
  assert.deepEqual(c.promotionIds, ['PROM-1']);
  assert.deepEqual(c.jobIds, ['JOB-1']);
  assert.deepEqual(c.specialistFindingIds, ['SF-1']);
  assert.match(c.correlationId, /^COR-/);
});

test('non-production findings remain visible as OUT_OF_SCOPE', () => {
  const policies = loadConfig().policies;
  // P0-13 requires the fine-grained scope classes, so `examples/` reports EXAMPLE
  // rather than collapsing into the older NON_PRODUCTION bucket.
  assert.equal(scopeOf('examples/demo.js', policies), 'EXAMPLE');
  assert.equal(scopeOf('docs/guide.md', policies), 'DOC');
  assert.equal(scopeOf('test/unit.js', policies), 'TEST');
  assert.equal(scopeOf('src/index.js', policies), 'PRODUCTION');
  assert.equal(scopeOf('dist/bundle.js', policies), 'GENERATED');
  assert.equal(scopeOf('vendor/left-pad.js', policies), 'NON_PRODUCTION');
  assert.equal(scopeOf('src/mystery', policies), 'PRODUCTION');
  assert.equal(scopeOf(null, policies), 'UNKNOWN');
  const result = correlate(root, [{ tool: 'semgrep', findings: [{ file: path.join(root, 'examples', 'demo.js'), line: 2, rule: 'r', detail: 'evidence' }] }], policies);
  assert.equal(result.candidates.length, 0);
  assert.equal(result.nonProductionSignals.length, 1);
  assert.equal(result.nonProductionSignals[0].disposition, 'OUT_OF_SCOPE');
  assert.equal(result.nonProductionSignals[0].scope, 'EXAMPLE');
});

test('specialist failure remains a failure and cannot erase a separate finding', () => {
  const failed = { tool: 'codeql', status: STATUS.ERROR, verdict: 'TOOL_ERROR', findings: [], coverage: { errors: ['timeout'] } };
  const succeeded = { tool: 'semgrep', status: STATUS.SUCCESS, verdict: '1_SIGNALS_FULL_COVERAGE', findings: [{ file: path.join(root, 'src', 'a.js'), line: 2, rule: 'r', detail: 'evidence' }], coverage: { errors: [] } };
  const verdict = auditVerdict([failed, succeeded], [{ disposition: 'PLAUSIBLE_SECURITY_ISSUE' }]);
  assert.equal(verdict.verdict, 'CANDIDATES_FOUND');
  assert.equal(verdict.analysisState, 'PARTIAL_ANALYSIS');
  assert.equal(verdict.candidateCount, 1);
});

// P0-17 determinism: semgrep prefixes local rule ids with the dotted config
// path, so the same ruleset yields different check_ids depending on where the
// audit is installed.  Finding identity must not depend on the install layout.
test('semgrep rule identity is independent of the config path', () => {
  const rule = 'sentinel.javascript.security.detect-child-process';
  assert.equal(normalizeSemgrepRuleId(`sentinel-audit.rules.semgrep.${rule}`), rule);
  assert.equal(normalizeSemgrepRuleId(`AppData.Local.Temp.opencode.alt-rules.${rule}`), rule);
  assert.equal(normalizeSemgrepRuleId(`some.other.install.path.${rule}`), rule);
});

test('semgrep rule normalization does not corrupt ids it does not own', () => {
  assert.equal(normalizeSemgrepRuleId('some.other.rule'), 'some.other.rule');
  assert.equal(normalizeSemgrepRuleId(null), '');
});

// The namespace-based restore above is only correct while every vendored rule
// declares it, otherwise a rule would keep its path-derived id.
test('every vendored Semgrep rule declares the stable id namespace', () => {
  const file = path.resolve(__dirname, '..', 'rules/semgrep/javascript-security.yml');
  const ids = [...fs.readFileSync(file, 'utf8').matchAll(/^\s*-\s*id:\s*(\S+)\s*$/gm)].map((m) => m[1]);
  assert.ok(ids.length >= 8, `expected vendored rules, found ${ids.length}`);
  for (const id of ids) assert.ok(id.startsWith('sentinel.'), `rule id is not namespaced: ${id}`);
  assert.equal(new Set(ids).size, ids.length, 'duplicate rule ids would collapse distinct findings');
});

test('remote Semgrep rulesets are never selected as local configs', () => {
  const ctx = { tools: { semgrep: { configs: ['p/security-audit', 'rules/semgrep'] } }, auditRoot: path.resolve(__dirname, '..') };
  const configs = localSemgrepConfigs(ctx);
  assert.equal(configs.length, 1);
  assert.equal(path.basename(configs[0]), 'semgrep');
  // The scan runs with cwd set to the audited repository, so a relative config
  // path would not resolve and semgrep would exit with a usage error.
  assert.ok(path.isAbsolute(configs[0]), 'semgrep config path must be absolute');
});

test('a missing local Semgrep ruleset resolves to no configs', () => {
  const ctx = { tools: { semgrep: { configs: ['p/secrets', 'rules/does-not-exist'] } }, auditRoot: path.resolve(__dirname, '..') };
  assert.deepEqual(localSemgrepConfigs(ctx), []);
});

// P0-19: a tool reporting a path outside the audited repository must not be able
// to steer correlation to an arbitrary file, and an empty target must not be
// mistaken for the repository root.
test('findings are confined to the audited repository', () => {
  const r = path.resolve(root);
  assert.equal(abs(r, 'src/a.js'), path.join(r, 'src', 'a.js'));
  assert.equal(abs(r, path.join(r, 'src', 'a.js')), path.join(r, 'src', 'a.js'));
  assert.equal(abs(r, '../../outside.js'), null);
  assert.equal(abs(r, path.resolve(r, '..', '..', 'outside.js')), null);
  assert.equal(abs(r, ''), null);
  assert.equal(abs(r, null), null);
  assert.equal(abs(r, './src/a.js'), path.join(r, 'src', 'a.js'));
});

test('SARIF parsing keeps every rule and location CodeQL reported', () => {
  const r = path.resolve(root);
  const sarif = {
    runs: [{ results: [
      { ruleId: 'js/clear-text-cookie', message: { text: 'hardcoded' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'examples/a.js' }, region: { startLine: 4 } } }] },
      { ruleId: 'js/sql-injection', message: { text: 'sql' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/b.js' }, region: { startLine: 9 } } }] },
    ] }],
  };
  const findings = parseSarif(r, sarif);
  assert.equal(findings.length, 2);
  assert.deepEqual(findings.map((f) => f.rule), ['js/clear-text-cookie', 'js/sql-injection']);
  assert.deepEqual(findings.map((f) => f.line), [4, 9]);
  assert.equal(findings[0].file, path.join(r, 'examples', 'a.js'));
  // A location outside the repository must never be clamped onto a real path
  // inside it, which would misattribute the finding.  It is retained with a null
  // file so the signal is not silently dropped.
  const escaped = parseSarif(r, { runs: [{ results: [
    { ruleId: 'r', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: '../../../etc/passwd' }, region: { startLine: 1 } } }] },
  ] }] });
  assert.equal(escaped.length, 1);
  assert.equal(escaped[0].file, null);
  assert.equal(escaped[0].rule, 'r');
});

test('configured Semgrep ruleset exists and is local', () => {
  const tools = loadConfig().tools;
  assert.deepEqual(tools.semgrep.configs, ['rules/semgrep']);
  assert.equal(tools.semgrep.allowRemoteRules, false);
  assert.ok(fs.existsSync(path.resolve(__dirname, '..', 'rules/semgrep/javascript-security.yml')));
});

// A single unreadable target makes semgrep exit non-zero AND return results: [].
// If that exit code were trusted on its own, one bad path would erase every real
// finding in the repository.  Targets must therefore be validated before the
// scan and rejected ones recorded rather than passed through.
test('unusable Semgrep targets are rejected before the scan, not after', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'targets-'));
  const good = path.join(dir, 'good.js');
  fs.writeFileSync(good, 'eval(x);\n');
  const sub = path.join(dir, 'sub');
  fs.mkdirSync(sub);
  // The escaping path has to exist, otherwise it is rejected as unreadable and
  // the containment check never gets the chance to fire.
  const outside = path.join(os.tmpdir(), `outside-${process.pid}.js`);
  fs.writeFileSync(outside, 'eval(x);\n');
  // A directory and the repository root are legitimate targets: rejecting them
  // is what made --routing directory and --routing repo scan nothing.
  const { usable, rejected } = usableTargets(dir, [good, sub, '.', path.join(dir, 'missing.js'), outside, '']);
  assert.deepEqual(usable, [good, sub, path.resolve(dir)], 'file, directory and repo root must all be usable');
  const reasons = rejected.map((r) => r.reason).join(' | ');
  assert.ok(reasons.includes('unreadable'), reasons);
  assert.ok(reasons.includes('outside'), reasons);
  assert.ok(reasons.includes('empty'), reasons);
  assert.equal(rejected.length, 3);
  fs.rmSync(outside, { force: true });
  fs.rmSync(dir, { recursive: true, force: true });
});

// semgrep prints "1.175.0" on stdout, writes an upgrade notice to stderr and can
// still exit non-zero.  Believing the exit code alone reported a working tool as
// INVALID, which silently removed it from the audit.
test('a version probe keeps a tool usable when it printed its version', () => {
  assert.equal(parseVersionOutput('1.175.0\r\n', '\r\nA new version of Semgrep is available\r\n'), '1.175.0');
  assert.equal(parseVersionOutput('', 'CodeQL command-line toolchain release 2.27.1.'), '2.27.1');
  assert.equal(parseVersionOutput('Version: 0.74.0', ''), '0.74.0');
  assert.equal(parseVersionOutput('no numbers here', 'still none'), null);
  assert.equal(parseVersionOutput(null, undefined), null);
});

// The cleartext-URL rule was the source of 17 findings on express, none of them
// real: it matched http:// inside comments and doc blocks, and it also matched
// https:// URLs, which is the opposite of the finding it claims to report.
test('the cleartext URL rule only accepts real plaintext endpoints', () => {
  const file = path.resolve(__dirname, '..', 'rules/semgrep/javascript-security.yml');
  const yaml = fs.readFileSync(file, 'utf8');
  const block = yaml.slice(yaml.indexOf('id: sentinel.javascript.security.audit.insecure-http-url'));
  const match = block.match(/regex:\s*'([^']+)'/);
  assert.ok(match, 'insecure-http-url rule must declare a URL regex');
  const re = new RegExp(match[1]);
  // Real cleartext traffic to a non-reserved host is the finding we want.
  assert.ok(re.test('http://legacy.internal.corp/api'), 'plaintext internal endpoint should match');
  assert.ok(re.test('http://legacy.internal.corp:8080/v1'), 'plaintext host on another port should match');
  // Everything below is noise that must not become a candidate.
  assert.equal(re.test('https://api.example.com/v1'), false, 'https must never match a cleartext rule');
  assert.equal(re.test('http://localhost:3000/users'), false, 'loopback must not match');
  assert.equal(re.test('http://127.0.0.1:8080/health'), false, 'loopback IP must not match');
  assert.equal(re.test('http://api.example.com/v1'), false, 'reserved documentation host must not match');
  assert.equal(re.test('http://insecure-service.example.net/v2'), false, 'reserved subdomain must not match');
  assert.equal(re.test('http://api.corp.example.org:8080/v1'), false, 'reserved host on another port must not match');
  assert.equal(re.test('ftp://example.org/x'), false, 'non-http schemes must not match');
  // The rule must be anchored to a string literal so comments cannot trigger it.
  assert.ok(yaml.includes(`- pattern: '"$URL"'`), 'rule must match a quoted literal, not raw text');
});

test('a retry rebases stale absolute targets onto the new worktree', () => {
  const from = path.resolve('C:/exec/run/worktree');
  const to = path.resolve('C:/exec/run/specialist-attempts/attempt-1/worktree');
  const rebased = rebaseTargets([path.join(from, 'lib', 'app.js'), path.join(from, 'test', 'a.js')], from, to);
  assert.deepEqual(rebased, [path.join(to, 'lib', 'app.js'), path.join(to, 'test', 'a.js')]);
});

test('rebasing leaves paths outside the old worktree untouched', () => {
  const from = path.resolve('C:/exec/run/worktree');
  const to = path.resolve('C:/exec/run/specialist-attempts/attempt-1/worktree');
  const outside = path.resolve('C:/somewhere/else/lib.js');
  // The adapter still owns the containment check; the helper must not widen it.
  assert.deepEqual(rebaseTargets([outside], from, to), [outside]);
  assert.deepEqual(rebaseTargets([from], from, to), [from]);
});

test('rebasing tolerates a non-array and an empty list', () => {
  assert.equal(rebaseTargets(undefined, 'C:/a', 'C:/b'), undefined);
  assert.deepEqual(rebaseTargets([], 'C:/a', 'C:/b'), []);
});

test('OSV exit 1 means vulnerabilities found, not a tool failure', () => {
  // osv-scanner exits 0 for clean and 1 for "results present".  Treating 1 as a
  // failure hides a successful scan behind a red status.
  assert.equal(osvExitSucceeded({ status: 0 }), true);
  assert.equal(osvExitSucceeded({ status: 1 }), true);
  assert.equal(osvExitSucceeded({ status: 127 }), false);
  assert.equal(osvExitSucceeded({ status: 128 }), false);
  assert.equal(osvExitSucceeded({ status: null }), false);
});

test('a failure reason is taken from the error line, not from progress noise', () => {
  const stderr = [
    'Scanning dir C:\\\\repo',
    'Starting filesystem walk for root: C:\\\\',
    'End status: 12 dirs visited, 31 inodes visited',
    'could not load db for npm ecosystem: unable to fetch OSV database',
  ].join('\n');
  assert.match(reasonFromStderr(stderr), /could not load db/);
  // With no error line at all, returning a progress line would be a lie.
  assert.equal(reasonFromStderr('End status: 12 dirs visited'), null);
  assert.equal(reasonFromStderr(''), null);
});

test('an oversized lockfile is still detected as a lockfile', () => {
  // The size guard exists to limit parsing, not to decide applicability.  When
  // an oversized lockfile was dropped, SCA reported "not applicable" on the
  // repository with the largest dependency tree instead of a coverage gap.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-lockfile-'));
  const policies = loadConfig().policies;
  const big = path.join(dir, 'pnpm-lock.yaml');
  fs.writeFileSync(big, '# lockfile\n' + 'x'.repeat(policies.coverage.maxFileBytes + 1024));
  const inv = inventory(dir, policies);
  assert.ok(fs.statSync(big).size > policies.coverage.maxFileBytes, 'fixture must exceed the size guard');
  assert.deepEqual(inv.lockfiles, ['pnpm-lock.yaml'], 'an oversized lockfile must still count as present');
  assert.ok(fs.readFileSync(big, 'utf8').length > policies.coverage.maxFileBytes);
  fs.rmSync(dir, { recursive: true, force: true });
});
