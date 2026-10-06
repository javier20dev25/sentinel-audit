'use strict';
/**
 * Routing end to end.
 *
 * The three routing modes are proven with a real specialist over a real git
 * repository: a real Semgrep binary, a real local rule set, real files, real
 * normalisation and real correlation.  Sentinel Cloud is the only substituted
 * component, because it is the remote engine; the signals it would return are
 * constructed here, and everything downstream of that boundary is production
 * code.
 *
 * The defect this guards against is specific: a mode that planned correctly but
 * handed the specialist nothing usable still produced a well formed report, so
 * the audit looked complete while scanning nothing.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { buildRoutePlan, promotionIdsForFinding } = require('../workflow/audit');
const { routeWithTargets, runSpecialistStage } = require('../workflow/pipeline-v1');
const { correlate, auditVerdict, openCandidates } = require('../correlate');
const { loadConfig, STATUS, envelope } = require('../lib/core');
const { localSemgrepConfigs } = require('../workflow/specialist-runtime');
const { abs: resolveTarget } = require('../workflow/paths');

const { tools, policies } = loadConfig();
const routingMap = policies.routing.signalToolMap;

function semgrepAvailable() {
  if (!localSemgrepConfigs({ auditRoot: path.resolve(__dirname, '..'), tools: tools }).length) return false;
  const probe = spawnSync('semgrep', ['--version'], { encoding: 'utf8', timeout: 60000 });
  return probe.status === 0;
}

// One file the rule set must flag, one it must not, spread across two
// directories so directory and repo scoping are distinguishable.
const VULNERABLE = 'const child = require("child_process");\nchild.exec(userInput);\n';
const CLEAN = 'function add(a, b) { return a + b; }\nmodule.exports = { add };\n';

function buildFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'routing-e2e-'));
  const git = (args) => spawnSync('git', args, { cwd: root, encoding: 'utf8' });
  git(['init', '-q']);
  git(['config', 'user.email', 'audit@test.invalid']);
  git(['config', 'user.name', 'Sentinel Audit Test']);
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.mkdirSync(path.join(root, 'lib'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'vulnerable.js'), VULNERABLE);
  fs.writeFileSync(path.join(root, 'lib', 'clean.js'), CLEAN);
  git(['add', '-A']);
  git(['commit', '-q', '-m', 'fixture']);
  return root;
}

function contextFor(root, work) {
  return {
    root,
    work,
    auditRoot: path.resolve(__dirname, '..'),
    tools,
    policies,
    inv: { mainLanguage: 'javascript' },
    pre: { cost: { requiredRamMB: 4096 } },
    toolResolutions: { semgrep: { available: true, name: 'semgrep', path: 'semgrep', state: 'AVAILABLE' } },
    timeoutFor: () => 120000,
  };
}

function cloudResult(root) {
  return {
    status: STATUS.PARTIAL,
    coverage: { engineExecutionComplete: true, coverageKnown: false },
    findings: [{
      signalId: 'SIG-E2E-1',
      file: path.join(root, 'src', 'vulnerable.js'),
      category: 'process',
      signalClass: 'ACTIONABLE_SIGNAL',
    }],
  };
}

test('routing reaches a real specialist in file, directory and repo mode', { skip: semgrepAvailable() ? false : 'semgrep is not installed on this host' }, async () => {
  const root = buildFixture();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'routing-work-'));
  const pre = { trackedFiles: ['src/vulnerable.js', 'lib/clean.js'], health: { semgrep: { available: true, name: 'semgrep', path: 'semgrep', state: 'AVAILABLE' } } };
  const ctx = contextFor(root, work);

  const observed = {};
  for (const mode of ['file', 'directory', 'repo']) {
    const sentinel = cloudResult(root);
    const plan = routeWithTargets(sentinel, root, pre, { routing: mode, only: ['semgrep'] });

    // The persisted contract is relative; the runtime resolves it.
    assert.ok(plan.targets.length > 0, `${mode}: the router must promote at least one target`);
    assert.ok(plan.targets.every((t) => !path.isAbsolute(t)), `${mode}: targets must not be absolute, got ${JSON.stringify(plan.targets)}`);
    assert.ok(plan.targets.every((t) => resolveTarget(root, t)), `${mode}: every target must resolve inside the repository`);

    // The router has to select the tracked files the mode implies, or the
    // specialist is being pointed at a directory that is not in scope.
    assert.ok(plan.filesSelected >= 1, `${mode}: no tracked file was selected`);

    const stage = await runSpecialistStage(root, ctx, plan, { only: ['semgrep'], maxHeavy: 1, maxLight: 1 }, `exec-e2e-${mode}`);
    const result = stage.results.semgrep;
    assert.ok(result, `${mode}: the specialist produced no result`);
    assert.notEqual(result.status, STATUS.ERROR, `${mode}: the specialist failed: ${result.error || ''}`);
    assert.notEqual(result.status, STATUS.UNAVAILABLE, `${mode}: the specialist was reported unavailable: ${result.error || ''}`);
    assert.equal(result.findingCount, (result.findings || []).length, `${mode}: the finding count must match the retained findings`);
    // The job ledger has to show the tool actually ran, with its own state.
    const job = (stage.jobs || []).find((record) => record.tool === 'semgrep');
    assert.ok(job, `${mode}: no job record for semgrep`);
    assert.equal(job.jobId, `exec-e2e-${mode}:semgrep`, `${mode}: job id was ${job.jobId}`);
    assert.ok(job.state, `${mode}: the job record has no state`);

    const vulnerable = (result.findings || []).filter((f) => path.resolve(f.file) === path.join(root, 'src', 'vulnerable.js'));
    assert.ok(vulnerable.length > 0, `${mode}: Semgrep found nothing in the promoted file (targets=${JSON.stringify(plan.targets)}, findings=${(result.findings || []).length})`);

    // Every finding must be attributed to a promotion that actually covers it,
    // which is only possible if the relative target resolved to the same
    // absolute path the tool reported.
    for (const finding of result.findings) {
      assert.ok((finding.promotionIds || []).length > 0, `${mode}: finding in ${finding.file} lost its promotion association`);
    }
    observed[mode] = { targets: plan.targets, filesSelected: plan.filesSelected, findings: result.findings.length };
  }

  // Each mode must actually be different, otherwise the modes are aliases and
  // the routing dimension carries no information.
  assert.deepEqual(observed.file.targets, ['src/vulnerable.js']);
  assert.deepEqual(observed.directory.targets, ['src']);
  assert.deepEqual(observed.repo.targets, ['.']);
  assert.equal(observed.repo.filesSelected, 2, 'repo mode must select every tracked file');
  assert.equal(observed.directory.filesSelected, 1, 'directory mode must select only the promoted directory');

  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(work, { recursive: true, force: true });
});

test('the three routing modes produce different, correct plans from the same signals', () => {
  const root = buildFixture();
  const signals = [{
    signalId: 'SIG-PLAN-1',
    file: path.join(root, 'src', 'vulnerable.js'),
    category: 'process',
    signalClass: 'ACTIONABLE_SIGNAL',
  }];
  const file = buildRoutePlan(signals, STATUS.PARTIAL, 'file', root, {}, routingMap);
  const directory = buildRoutePlan(signals, STATUS.PARTIAL, 'directory', root, {}, routingMap);
  const repo = buildRoutePlan(signals, STATUS.PARTIAL, 'repo', root, {}, routingMap);

  assert.deepEqual(file.targets, ['src/vulnerable.js']);
  assert.deepEqual(directory.targets, ['src']);
  assert.deepEqual(repo.targets, ['.']);
  // Promotion identity must be stable across rebuilds of the same plan, since
  // it is what correlates a finding to the signal that justified it.
  assert.equal(
    buildRoutePlan(signals, STATUS.PARTIAL, 'file', root, {}, routingMap).promotions[0].promotionId,
    file.promotions[0].promotionId,
  );
  // A root level signal in directory mode expands to the root, and that has to
  // be recorded rather than hidden.
  const rootLevel = buildRoutePlan([{ signalId: 'SIG-ROOT', file: path.join(root, 'top.js'), category: 'process', signalClass: 'ACTIONABLE_SIGNAL' }], STATUS.PARTIAL, 'directory', root, {}, routingMap);
  assert.deepEqual(rootLevel.targets, ['.']);
  assert.equal(rootLevel.promotions[0].rootLevelExpansion, true);

  fs.rmSync(root, { recursive: true, force: true });
});

test('a finding is associated with the promotion that covers it in every mode', () => {
  const root = buildFixture();
  const signals = [{
    signalId: 'SIG-ASSOC-1',
    file: path.join(root, 'src', 'vulnerable.js'),
    category: 'process',
    signalClass: 'ACTIONABLE_SIGNAL',
  }];
  const finding = { file: path.join(root, 'src', 'vulnerable.js') };
  for (const mode of ['file', 'directory', 'repo']) {
    const plan = buildRoutePlan(signals, STATUS.PARTIAL, mode, root, {}, routingMap);
    const ids = promotionIdsForFinding(finding, plan, mode, root);
    assert.deepEqual(ids, plan.promotions.map((p) => p.promotionId), `${mode}: the finding lost its promotion association`);
  }
  // A file outside every promoted target must not inherit a promotion.
  const filePlan = buildRoutePlan(signals, STATUS.PARTIAL, 'file', root, {}, routingMap);
  assert.deepEqual(promotionIdsForFinding({ file: path.join(root, 'lib', 'clean.js') }, filePlan, 'file', root), []);
  // A repository scoped finding is handled by the repository wide specialists.
  const repoPlan = buildRoutePlan(signals, STATUS.PARTIAL, 'repo', root, {}, routingMap);
  assert.deepEqual(promotionIdsForFinding(finding, repoPlan, 'REPOSITORY', root), []);

  fs.rmSync(root, { recursive: true, force: true });
});

test('specialist findings survive normalisation, correlation and the verdict', async () => {
  const root = buildFixture();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'routing-corr-'));
  const pre = { trackedFiles: ['src/vulnerable.js', 'lib/clean.js'], health: { semgrep: { available: true, name: 'semgrep', path: 'semgrep', state: 'AVAILABLE' } } };
  const ctx = contextFor(root, work);
  const sentinel = cloudResult(root);
  const plan = routeWithTargets(sentinel, root, pre, { routing: 'file', only: ['semgrep'] });
  const stage = await runSpecialistStage(root, ctx, plan, { only: ['semgrep'], maxHeavy: 1, maxLight: 1 }, 'exec-corr');
  const result = stage.results.semgrep;
  assert.ok(result && (result.findings || []).length > 0, `the specialist must produce findings to correlate, got ${result && result.status}: ${result && result.error || 'none'}`);

  // Correlate exactly as the pipeline does, with envelopes built by the real
  // envelope() factory: the Cloud engine under its own tool name and the
  // specialist under its own.  Hand-rolling these would test a shape the
  // pipeline never produces.
  const envelopes = [
    envelope('sentinel', {
      status: STATUS.PARTIAL,
      coverage: { coverageKnown: false, coverageUnknown: true, analysisCompleted: true },
      findings: (sentinel.findings || []).map((finding) => ({ ...finding })),
    }),
    result,
  ];
  const joined = correlate(root, envelopes, policies);

  assert.ok((joined.candidates || []).length + (joined.observations || []).length > 0, 'correlation must retain the specialist findings as candidates or observations');
  const retained = (joined.candidates || []).length + (joined.observations || []).length;
  assert.ok(retained >= 1, `correlation discarded every signal (candidates=${(joined.candidates || []).length}, observations=${(joined.observations || []).length})`);
  const verdict = auditVerdict(envelopes, openCandidates(joined.candidates || []));
  assert.ok(verdict, 'a verdict must be produced from real findings');
  // Coverage was never established by Cloud, so no clean claim may survive.
  assert.equal(verdict.canClaimClean, false, 'an audit with unknown coverage must not be able to claim clean');
  assert.ok(verdict.statement.length > 0, 'the verdict must state its reasoning');

  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(work, { recursive: true, force: true });
});
