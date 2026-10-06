'use strict';
/**
 * Sentinel Audit v1 pipeline.
 *
 * The pipeline is intentionally boring: each stage writes an artifact before
 * the next begins, failures stay local to the stage, and no stage interprets
 * absence as a security-clean verdict.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const A = require('../adapters');
const { loadConfig, STATUS, EXT_LANG, dirBytes } = require('../lib/core');
const { preflight } = require('./preflight');
const { buildIdentity } = require('./identity');
const { buildRoutePlan, promotionIdsForFinding } = require('./audit');
const { correlate, auditVerdict, openCandidates } = require('../correlate');
const { renderReport } = require('../reports/expediente');
const { ResourceScheduler } = require('./scheduler');
const { executeSpecialist, specialistOutcome } = require('./specialist-runtime');
const { initExecution, contained, writeJson, manifest, verifyManifest } = require('./artifacts');
const { createManagedCheckout, cleanupManagedCheckout, rebaseTargets } = require('./workspace');
const { installCancellation } = require('./cancellation');
const { abs: resolveTarget, relTarget } = require('./paths');

const ALL_SPECIALISTS = ['codeql', 'semgrep', 'trivy', 'osv'];
const HEAVY = new Set(['codeql']);

function hash(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function now() { return new Date().toISOString(); }

function outputRoot(opts = {}) {
  const chosen = opts.output || path.join(__dirname, '..', 'out');
  const root = path.resolve(chosen);
  fs.mkdirSync(root, { recursive: true });
  const probe = path.join(root, `.sentinel-audit-probe-${process.pid}-${Date.now()}`);
  try { fs.writeFileSync(probe, 'ok', { flag: 'wx' }); fs.unlinkSync(probe); }
  catch (error) { throw new Error(`output path is not writable: ${root}: ${error.message}`); }
  return root;
}

function slugOf(value) { return String(value || 'target').replace(/[^A-Za-z0-9_.-]+/g, '_').slice(0, 80) || 'target'; }
function executionId() { return `exec-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomUUID()}`; }

function expectedCommit(opts, pre) {
  const requested = opts.commit || null;
  if (requested && !/^[0-9a-f]{40}$/i.test(requested)) throw new Error('--commit must be an exact 40-character SHA');
  if (!requested) throw new Error('--commit is required for an immutable Sentinel Audit run');
  if (!pre.commit || pre.commit.toLowerCase() !== requested.toLowerCase()) throw new Error(`requested commit ${requested} does not match source HEAD ${pre.commit || 'unknown'}`);
  return requested.toLowerCase();
}

function stageStore(executionDir, stages) {
  writeJson(contained(executionDir, 'state', 'stages.json'), stages, { overwrite: true });
}

function markStage(executionDir, stages, name, state, detail = null) {
  stages[name] = { state, at: now(), detail };
  stageStore(executionDir, stages);
}

function safeWriteExecution(executionDir, expediente) {
  expediente.updatedAt = now();
  writeJson(contained(executionDir, 'expediente.json'), expediente, { overwrite: true });
  writeJson(contained(executionDir, 'report', 'REPORT.json'), expediente, { overwrite: true });
}

function timeoutFor(tool, policies, opts) {
  const override = opts.timeoutMs;
  if (Number.isInteger(override) && override > 0) return override;
  const minutes = policies.budget.perToolMinutes[tool] || 5;
  return minutes * 60 * 1000;
}

function makeContext(root, executionDir, pre, options) {
  const { tools, policies } = loadConfig();
  return {
    root,
    work: executionDir,
    auditRoot: path.resolve(__dirname, '..'),
    tools,
    policies,
    provider: options.provider === 'cloud' ? 'cloud' : 'local',
    inv: pre.inv,
    pre,
    toolResolutions: pre.health,
    toolOverrides: options.toolOverrides || null,
    keepDb: !!options.keepWorktree,
    timeoutFor: (tool) => timeoutFor(tool, policies, options),
  };
}

function routeWithTargets(sentinel, root, pre, opts) {
  const { policies } = loadConfig();
  const mode = opts.routing || policies.routing.defaultMode;
  if (!policies.routing.supportedModes.includes(mode)) throw new Error(`invalid routing mode: ${mode}`);
  const actionable = (sentinel.findings || []).filter((finding) => finding.signalClass === 'ACTIONABLE_SIGNAL');
  const plan = buildRoutePlan(actionable, sentinel.status, mode, root, sentinel.coverage || {}, policies.routing.signalToolMap);
  // Targets are persisted relative to the repository, so every comparison below
  // has to go through the root of this execution.  path.resolve() on its own
  // resolves against the process cwd and would match no tracked file at all,
  // leaving filesSelected at 0 and every target silently unpromoted.
  const absoluteTarget = (target) => resolveTarget(root, target);
  plan.directoryRootFilePolicy = policies.routing.directoryRootFilePolicy;
  plan.targetEntries = (plan.promotions || []).map((promotion) => ({
    target: promotion.target,
    status: 'PROMOTED',
    scope: mode,
    reason: promotion.reason,
    promotionId: promotion.promotionId,
    sourceSignalIds: promotion.signalIds,
    rootLevelExpansion: mode === 'directory' && absoluteTarget(promotion.target) === path.resolve(root),
  }));
  const sourceFiles = (pre.trackedFiles || []).filter((file) => EXT_LANG[path.extname(file).toLowerCase()]);
  const selected = new Set();
  for (const target of plan.targets || []) {
    const absolute = absoluteTarget(target);
    if (!absolute) continue;
    for (const rel of sourceFiles) {
      const file = path.resolve(root, rel);
      if (mode === 'repo' || file === absolute || (mode === 'directory' && file.startsWith(absolute + path.sep))) selected.add(rel);
    }
  }
  plan.files = sourceFiles.filter((file) => selected.has(file));
  plan.notPromoted = sourceFiles.filter((file) => !selected.has(file)).map((file) => ({ file, status: 'NOT_PROMOTED', reason: 'not selected for a downstream stage; not a safety or clean judgment' }));
  plan.filesSelected = plan.files.length;
  plan.filesExcludedCount = plan.notPromoted.length;
  plan.coverage = {
    engineExecutionComplete: !!(sentinel.coverage && sentinel.coverage.engineExecutionComplete),
    engineIncomplete: !!(sentinel.coverage && sentinel.coverage.engineIncomplete),
    coverageKnown: !!(sentinel.coverage && sentinel.coverage.coverageKnown),
    coverageUnknown: !(sentinel.coverage && sentinel.coverage.coverageKnown),
    filesScanned: sentinel.coverage ? sentinel.coverage.filesScanned ?? null : null,
    filesFailed: sentinel.coverage ? sentinel.coverage.filesFailed ?? null : null,
    alertsSeen: sentinel.coverage ? sentinel.coverage.alertsSeen ?? null : null,
    alertsEnrichFailed: sentinel.coverage ? sentinel.coverage.alertsEnrichFailed ?? null : null,
    degradationSamples: sentinel.coverage ? sentinel.coverage.degradationSamples ?? null : null,
  };
  return plan;
}

function specialistTools(plan, opts) {
  const routed = (plan.tools || []).filter((tool) => ALL_SPECIALISTS.includes(tool));
  const only = opts.only && opts.only.length ? [...new Set(opts.only)] : routed;
  const skip = new Set(opts.skip || []);
  const invalidOnly = only.filter((tool) => !routed.includes(tool));
  const invalidSkip = [...skip].filter((tool) => !ALL_SPECIALISTS.includes(tool));
  if (invalidOnly.length || invalidSkip.length) throw new Error(`invalid specialist selection: unrouted --only=${invalidOnly.join(',') || 'none'} unknown --skip=${invalidSkip.join(',') || 'none'}`);
  return routed.map((tool) => ({ tool, requested: only.includes(tool) && !skip.has(tool), skipped: skip.has(tool) || !only.includes(tool) }));
}

function enrichSpecialistResult(result, tool, job, route, root) {
  // 'REPOSITORY' marks a tool that always scans the whole repository on its own
  // terms (CodeQL, Trivy, OSV), so no signal promotion applies to it.  The repo
  // *routing mode* is a different thing: Semgrep there is still running against
  // a promoted target, and conflating the two dropped the attribution of every
  // finding in repo mode.
  const scopeMode = ['codeql', 'trivy', 'osv'].includes(tool) ? 'REPOSITORY' : route.mode;
  const findings = (result.findings || []).map((finding, index) => {
    const promotionIds = promotionIdsForFinding(finding, route, scopeMode, root);
    return Object.assign({}, finding, {
      specialistFindingId: `SF-${hash(JSON.stringify([job.id, finding.rule || finding.kind || '', finding.file || '', finding.line || null, index])).slice(0, 16)}`,
      jobId: job.id,
      promotionIds,
      scopeMode,
    });
  });
  return Object.assign({}, result, { tool, findings, findingCount: findings.length, jobId: job.id, scopeMode });
}

async function runSpecialistStage(root, ctx, route, opts, executionIdValue) {
  const resources = ctx.policies.resources;
  const scheduler = new ResourceScheduler({ maxHeavy: opts.maxHeavy || resources.maxHeavy, maxLight: opts.maxLight || resources.maxLight });
  // An interrupt has to stop the specialists that are already running, not only
  // the ones still queued: a killed CodeQL database build would otherwise be
  // recorded as if it had completed.
  const onInterrupt = () => { for (const job of scheduler.snapshot()) scheduler.cancel(job.id); };
  if (opts.signal) {
    if (opts.signal.aborted) onInterrupt();
    else opts.signal.addEventListener('abort', onInterrupt, { once: true });
  }
  const jobs = [];
  const results = {};
  for (const selection of specialistTools(route, opts)) {
    const tool = selection.tool;
    const id = `${executionIdValue}:${tool}`;
    const resourceClass = HEAVY.has(tool) ? 'HEAVY' : 'LIGHT';
    if (!selection.requested) {
      const skipped = { tool, status: STATUS.SKIPPED, verdict: 'SKIPPED', findings: [], findingCount: 0, notApplicable: false, error: 'specialist skipped by explicit CLI policy', coverage: { coverageKnown: false, coverageUnknown: true, analysisCompleted: false, errors: ['skipped by request'] }, cost: { wallClockMs: 0, timedOut: false }, job: { jobId: id, resourceClass, state: 'CANCELLED', queuedAt: now(), startedAt: null, finishedAt: now(), durationMs: 0 } };
      results[tool] = skipped;
      jobs.push(skipped.job);
      continue;
    }
    const job = scheduler.add({
      id,
      resourceClass,
      run: async (runtime) => {
        const result = await executeSpecialist(tool, root, ctx, Object.assign({ id, resourceClass }, runtime), {
          language: ctx.inv.mainLanguage,
          ram: ctx.pre.cost.requiredRamMB,
          targets: route.targets,
        });
        return { state: result.job && result.job.state || 'SUCCEEDED', result };
      },
    });
    jobs.push(job);
  }
  const completed = await scheduler.drain();
  for (const job of completed) {
    const rawResult = job.result && job.result.result;
    if (rawResult) results[job.id.split(':').pop()] = enrichSpecialistResult(rawResult, job.id.split(':').pop(), job, route, root);
    else {
      const tool = job.id.split(':').pop();
      results[tool] = { tool, status: STATUS.ERROR, verdict: 'TOOL_ERROR', findings: [], findingCount: 0, error: job.result && job.result.error || 'scheduler job failed', coverage: { coverageKnown: false, coverageUnknown: true, analysisCompleted: false, errors: ['scheduler job failed'] }, cost: { wallClockMs: job.durationMs || 0, timedOut: job.state === 'TIMEOUT' }, job: { jobId: job.id, resourceClass: job.resourceClass, state: job.state, queuedAt: job.queuedAt, startedAt: job.startedAt, finishedAt: job.finishedAt, durationMs: job.durationMs } };
    }
  }
  const records = Object.values(results).map((result) => Object.assign({
    tool: result.tool, status: result.status, findingCount: result.findingCount, rawArtifact: result.rawArtifact || null,
    availability: result.availability || null, scopeMode: result.scopeMode || null,
    // The explicit outcome, so the ledger distinguishes "never ran here" from
    // "ran and broke" without the reader having to infer it from a status.
    outcome: specialistOutcome(result),
  }, result.job || {}));
  return { results, jobs: records, scheduler: scheduler.snapshot() };
}

function stageFailure(tool, error) {
  return { tool, status: STATUS.ERROR, verdict: 'TOOL_ERROR', findings: [], findingCount: 0, notApplicable: false, error: String(error && error.message || error), coverage: { coverageKnown: false, coverageUnknown: true, analysisCompleted: false, errors: [String(error && error.message || error)] }, cost: { wallClockMs: 0, timedOut: false } };
}

function applyCorrelation(expediente, envelopes, root, policies, executionDir) {
  try {
    const joined = correlate(root, envelopes, policies);
    for (const candidate of joined.candidates) {
      candidate.commit = expediente.commit;
      candidate.repository = expediente.repository;
      candidate.repo = expediente.repository;
      candidate.tree = expediente.tree;
    }
    expediente.candidates = joined.candidates;
    expediente.observations = joined.observations;
    expediente.nonProductionSignals = joined.nonProductionSignals;
    writeJson(contained(executionDir, 'correlation', 'findings.json'), envelopes.flatMap((envelope) => (envelope.findings || []).map((finding) => Object.assign({ tool: envelope.tool }, finding))), { overwrite: true });
    writeJson(contained(executionDir, 'correlation', 'candidates.json'), joined.candidates, { overwrite: true });
    writeJson(contained(executionDir, 'correlation', 'candidate-ledger.json'), joined.candidates, { overwrite: true });
    writeJson(contained(executionDir, 'correlation', 'out-of-scope.json'), joined.nonProductionSignals, { overwrite: true });
    return null;
  } catch (error) {
    const failure = stageFailure('correlation', error);
    writeJson(contained(executionDir, 'correlation', 'error.json'), failure, { overwrite: true });
    expediente.candidates = [];
    expediente.observations = [];
    expediente.nonProductionSignals = [];
    return failure;
  }
}

function updateAuditVerdict(expediente, envelopes, extraFailure = null) {
  const all = extraFailure ? [...envelopes, extraFailure] : envelopes;
  expediente.auditVerdict = auditVerdict(all, openCandidates(expediente.candidates || []));
  return expediente.auditVerdict;
}

function finalizeArtifacts(executionDir, expediente, stages) {
  safeWriteExecution(executionDir, expediente);
  try { renderReport(expediente); }
  catch (error) { writeJson(contained(executionDir, 'report', 'render-error.json'), { error: String(error.message || error) }, { overwrite: true }); }
  stageStore(executionDir, stages);
  return manifest(executionDir, { pipelineStatus: expediente.pipelineStatus, auditVerdict: expediente.auditVerdict && expediente.auditVerdict.verdict, cleanupStatus: expediente.cleanup && expediente.cleanup.cleanupStatus });
}

function exitCodeFor(expediente) {
  if (expediente.preflight && expediente.preflight.verdict === 'SKIP') return 3;
  if (expediente.auditVerdict && expediente.auditVerdict.candidateCount > 0) return 1;
  if (expediente.auditVerdict && expediente.auditVerdict.analysisState !== 'FULL') return 2;
  if (expediente.cleanup && expediente.cleanup.cleanupStatus !== 'CLEAN') return 2;
  return 0;
}

async function runAuditV1(sourceRepo, options = {}) {
  const { tools, policies } = loadConfig();
  const sourcePreflight = preflight(sourceRepo, { name: options.name, commit: options.commit, toolOverrides: options.toolOverrides, provider: options.provider, apiUrl: options.apiUrl });
  const commit = expectedCommit(options, sourcePreflight);
  const rootOut = outputRoot(options);
  const id = executionId();
  const name = slugOf(options.name || path.basename(path.resolve(sourceRepo)));
  const executionDir = initExecution(rootOut, name, id);
  // Registered before the first stage runs so an interrupt during Cloud or
  // checkout is recorded rather than losing the execution.
  const cancellation = new AbortController();
  const disposeCancellation = installCancellation({
    executionDir,
    controller: cancellation,
    cleanup: () => { try { cleanupManagedCheckout(executionDir, { keepWorktree: false }); } catch (error) { /* cleanup is best effort after an interrupt */ } },
    log: (message) => process.stderr.write(`${message}\n`),
  });
  const stages = {};
  markStage(executionDir, stages, 'PREFLIGHT', sourcePreflight.verdict === 'SKIP' ? 'FAILED' : 'COMPLETE', sourcePreflight.reasons);

  const skeleton = {
    schema: 'sentinel-audit-expediente/1.0.0', executionId: id, artifactDir: executionDir,
    sourceRepository: path.resolve(sourceRepo), repository: null, name, commit, tree: null, remoteUrl: sourcePreflight.remoteUrl || null,
    cloudProvider: options.provider === 'cloud' ? 'cloud' : 'local',
    startedAt: now(), pipelineStatus: 'RUNNING', preflight: sourcePreflight,
    tools: {}, signalRouting: null, candidates: [], observations: [], nonProductionSignals: [],
    specialistJobs: [], publication: policies.publication, cleanup: null, auditVerdict: null,
    stages,
  };
  if (sourcePreflight.verdict === 'SKIP') {
    skeleton.pipelineStatus = 'PREFLIGHT_FAILED';
    skeleton.auditVerdict = { verdict: 'PREFLIGHT_FAILED', analysisState: 'PARTIAL_ANALYSIS', canClaimClean: false, candidateCount: 0, statement: sourcePreflight.reasons.join('; ') };
    finalizeArtifacts(executionDir, skeleton, stages);
    return { executionDir, expediente: skeleton, exitCode: 3 };
  }
  if (options.dryRun) {
    skeleton.pipelineStatus = 'DRY_RUN';
    skeleton.auditVerdict = { verdict: 'DRY_RUN', analysisState: 'PARTIAL_ANALYSIS', canClaimClean: false, candidateCount: 0, statement: 'No scanner or specialist was executed because --dry-run was supplied.' };
    markStage(executionDir, stages, 'IDENTITY', 'PLANNED');
    markStage(executionDir, stages, 'CLOUD', 'NOT_RUN');
    finalizeArtifacts(executionDir, skeleton, stages);
    return { executionDir, expediente: skeleton, exitCode: 2 };
  }

  let workspace = null;
  try {
    workspace = createManagedCheckout(sourceRepo, commit, executionDir, { timeoutMs: options.workspaceTimeoutMs });
    const targetPreflight = preflight(workspace.path, { name, commit, toolOverrides: options.toolOverrides, provider: options.provider, apiUrl: options.apiUrl });
    if (targetPreflight.verdict === 'SKIP') throw new Error(`managed checkout preflight failed: ${targetPreflight.reasons.join('; ')}`);
    skeleton.repository = workspace.path;
    skeleton.tree = workspace.tree;
    skeleton.remoteUrl = workspace.remoteUrl || sourcePreflight.remoteUrl || null;
    skeleton.preflight = targetPreflight;
    skeleton.identity = buildIdentity({ executionId: id, repo: workspace.path, preflight: targetPreflight, tools: targetPreflight.health, startedAt: skeleton.startedAt, sourceRepository: sourceRepo });
    writeJson(contained(executionDir, 'identity.json'), skeleton.identity);
    markStage(executionDir, stages, 'IDENTITY', 'COMPLETE', { commit, tree: workspace.tree });

    const ctx = makeContext(workspace.path, executionDir, targetPreflight, options);
    const sentinel = ctx.provider === 'cloud'
      ? await A.hosted(workspace.path, ctx, options)
      : await A.sentinel(workspace.path, ctx);
    skeleton.tools.sentinel = sentinel;
    if (!fs.existsSync(contained(executionDir, 'cloud', 'raw.json'))) {
      // A hosted run that failed before producing evidence must not borrow the
      // local engine's identity for its raw artifact.
      writeJson(contained(executionDir, 'cloud', 'raw.json'), ctx.provider === 'cloud'
        ? { mode: 'hosted', error: sentinel.error || null, result: null }
        : { engine: targetPreflight.health.sentinel || null, error: sentinel.error || null, result: null });
    }
    writeJson(contained(executionDir, 'cloud', 'normalized.json'), sentinel.findings || []);
    markStage(executionDir, stages, 'CLOUD', sentinel.status === STATUS.ERROR ? 'FAILED' : 'COMPLETE', { status: sentinel.status, rawArtifact: sentinel.rawArtifact || null });

    const route = routeWithTargets(sentinel, workspace.path, targetPreflight, options);
    route.executionId = id;
    skeleton.signalRouting = route;
    writeJson(contained(executionDir, 'routing', 'targets.json'), { mode: route.mode, targets: route.targetEntries, filesSelected: route.filesSelected, notPromoted: route.notPromoted });
    writeJson(contained(executionDir, 'routing', 'decisions.json'), route);
    markStage(executionDir, stages, 'ROUTING', route.engineIncomplete ? 'INCOMPLETE' : 'COMPLETE', { decision: route.decision, targetCount: route.targetEntries.length });

    if (options.scanOnly) {
      skeleton.specialistJobs = [];
      skeleton.resourceMetrics = { limits: { maxHeavy: options.maxHeavy || policies.resources.maxHeavy, maxLight: options.maxLight || policies.resources.maxLight }, scheduler: [] };
      writeJson(contained(executionDir, 'specialist-jobs.json'), []);
      markStage(executionDir, stages, 'SPECIALISTS', 'NOT_RUN', 'scan command stops after Cloud normalization and routing');
    } else {
      const specialistStage = await runSpecialistStage(workspace.path, ctx, route, Object.assign({}, options, { signal: cancellation.signal }), id);
      Object.assign(skeleton.tools, specialistStage.results);
      skeleton.specialistJobs = specialistStage.jobs;
      skeleton.resourceMetrics = { limits: { maxHeavy: options.maxHeavy || policies.resources.maxHeavy, maxLight: options.maxLight || policies.resources.maxLight }, scheduler: specialistStage.scheduler };
      writeJson(contained(executionDir, 'specialist-jobs.json'), specialistStage.jobs);
      for (const [tool, result] of Object.entries(specialistStage.results)) writeJson(contained(executionDir, 'specialists', tool, 'normalized.json'), result.findings || [], { overwrite: true });
      markStage(executionDir, stages, 'SPECIALISTS', 'COMPLETE', { jobs: specialistStage.jobs.length });
    }

    const envelopes = Object.values(skeleton.tools);
    const correlationFailure = applyCorrelation(skeleton, envelopes, workspace.path, policies, executionDir);
    markStage(executionDir, stages, 'CORRELATION', correlationFailure ? 'FAILED' : 'COMPLETE', correlationFailure && correlationFailure.error);
    updateAuditVerdict(skeleton, envelopes, options.scanOnly && !correlationFailure
      ? stageFailure('specialist-stage', 'scan-only execution: specialists were intentionally not run')
      : correlationFailure);
    markStage(executionDir, stages, 'TRIAGE', 'COMPLETE', { verdict: skeleton.auditVerdict.verdict, candidateCount: skeleton.auditVerdict.candidateCount });
    skeleton.pipelineStatus = options.scanOnly ? 'SCAN_COMPLETE_PENDING_SPECIALISTS' : 'COMPLETE';
  } catch (error) {
    skeleton.pipelineStatus = 'INFRASTRUCTURE_FAILURE';
    skeleton.pipelineFailure = String(error && error.message || error);
    skeleton.auditVerdict = { verdict: 'PARTIAL_ANALYSIS', analysisState: 'PARTIAL_ANALYSIS', canClaimClean: false, candidateCount: 0, statement: `Pipeline infrastructure failure: ${skeleton.pipelineFailure}` };
    markStage(executionDir, stages, 'PIPELINE', 'FAILED', skeleton.pipelineFailure);
  } finally {
    skeleton.finishedAt = now();
    skeleton.totalWallClockMs = new Date(skeleton.finishedAt) - new Date(skeleton.startedAt);
    skeleton.cleanup = cleanupManagedCheckout(executionDir, { keepWorktree: !!options.keepWorktree });
    markStage(executionDir, stages, 'CLEANUP', skeleton.cleanup.cleanupStatus, skeleton.cleanup.cleanupErrors);
    if (skeleton.cleanup.cleanupStatus !== 'CLEAN' && skeleton.auditVerdict) {
      skeleton.auditVerdict.analysisState = 'PARTIAL_ANALYSIS';
      skeleton.auditVerdict.canClaimClean = false;
      skeleton.auditVerdict.statement += ' Cleanup did not complete; retained paths are listed in cleanup.json.';
    }
    writeJson(contained(executionDir, 'cleanup.json'), skeleton.cleanup, { overwrite: true });
    skeleton.artifactBytes = dirBytes(executionDir);
    finalizeArtifacts(executionDir, skeleton, stages);
  }
  disposeCancellation();
  return { executionDir, expediente: skeleton, exitCode: exitCodeFor(skeleton) };
}

function loadExecution(executionDir) {
  const root = path.resolve(executionDir);
  const file = contained(root, 'expediente.json');
  if (!fs.existsSync(file)) throw new Error('execution directory has no expediente.json');
  const integrity = verifyManifest(root);
  if (!integrity.ok) throw new Error(`artifact integrity verification failed: ${integrity.errors.join('; ')}`);
  return { root, expediente: JSON.parse(fs.readFileSync(file, 'utf8')) };
}

function rerenderExecution(executionDir) {
  const { root, expediente } = loadExecution(executionDir);
  renderReport(expediente);
  writeJson(contained(root, 'report', 'REPORT.json'), expediente, { overwrite: true });
  manifest(root, { pipelineStatus: expediente.pipelineStatus, rerendered: true });
  return { executionDir: root, expediente, exitCode: exitCodeFor(expediente) };
}

function rerouteExecution(executionDir, options = {}) {
  const { root, expediente } = loadExecution(executionDir);
  const sentinel = expediente.tools && expediente.tools.sentinel;
  if (!sentinel) throw new Error('saved execution has no Cloud result');
  const pseudoPreflight = expediente.preflight;
  const repo = expediente.repository || expediente.sourceRepository;
  const route = routeWithTargets(sentinel, repo, pseudoPreflight, options);
  route.executionId = expediente.executionId;
  expediente.signalRouting = route;
  writeJson(contained(root, 'routing', 'targets.json'), { mode: route.mode, targets: route.targetEntries, filesSelected: route.filesSelected, notPromoted: route.notPromoted }, { overwrite: true });
  writeJson(contained(root, 'routing', 'decisions.json'), route, { overwrite: true });
  safeWriteExecution(root, expediente);
  manifest(root, { pipelineStatus: expediente.pipelineStatus, rerouted: true });
  return { executionDir: root, expediente, exitCode: exitCodeFor(expediente) };
}

function cleanupExecution(executionDir, options = {}) {
  const { root, expediente } = loadExecution(executionDir);
  const cleanup = cleanupManagedCheckout(root, { keepWorktree: !!options.keepWorktree });
  expediente.cleanup = cleanup;
  if (cleanup.cleanupStatus !== 'CLEAN' && expediente.auditVerdict) {
    expediente.auditVerdict.analysisState = 'PARTIAL_ANALYSIS';
    expediente.auditVerdict.canClaimClean = false;
  }
  safeWriteExecution(root, expediente);
  writeJson(contained(root, 'cleanup.json'), cleanup, { overwrite: true });
  manifest(root, { pipelineStatus: expediente.pipelineStatus, cleanupStatus: cleanup.cleanupStatus });
  return { executionDir: root, expediente, exitCode: exitCodeFor(expediente) };
}

/**
 * Retry only previously unfinished specialists.  It never reruns Cloud, never
 * overwrites a prior raw artifact, and builds a fresh disposable checkout for
 * the retry so a completed cleanup does not make the execution unresumable.
 */
async function continueSpecialists(executionDir, options = {}) {
  const { root, expediente } = loadExecution(executionDir);
  if (!expediente.identity || !expediente.signalRouting || !expediente.tools || !expediente.tools.sentinel) throw new Error('execution lacks identity, Cloud evidence, or routing state');
  const routed = (expediente.signalRouting.tools || []).filter((tool) => ALL_SPECIALISTS.includes(tool));
  const terminal = new Set([STATUS.ERROR, STATUS.UNAVAILABLE, STATUS.INVALID, STATUS.TIMEOUT, STATUS.CANCELLED, STATUS.SKIPPED]);
  const requested = options.only && options.only.length
    ? [...new Set(options.only)]
    : routed.filter((tool) => !expediente.tools[tool] || terminal.has(expediente.tools[tool].status));
  const invalid = requested.filter((tool) => !routed.includes(tool));
  if (invalid.length) throw new Error(`requested specialist is not justified by the saved route: ${invalid.join(', ')}`);
  if (!requested.length) return { executionDir: root, expediente, exitCode: exitCodeFor(expediente), skipped: 'no unfinished routed specialist job' };

  // Kept deliberately short.  A full ISO timestamp plus a 36 character UUID
  // pushed the nested worktree/.git path past the Windows 260 character limit,
  // which failed the clone with "$GIT_DIR too big" and turned a retry into an
  // infrastructure error.  The full identifier is kept in the written state.
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace(/^\d{4}-\d{2}-\d{2}T/, '');
  const attemptId = `attempt-${stamp}-${crypto.randomUUID().slice(0, 8)}`;
  const attemptDir = contained(root, 'specialist-attempts', attemptId);
  fs.mkdirSync(attemptDir, { recursive: true });
  let workspace;
  try {
    workspace = createManagedCheckout(expediente.sourceRepository, expediente.commit, attemptDir, {});
    const pre = preflight(workspace.path, { name: expediente.name, commit: expediente.commit, toolOverrides: options.toolOverrides, provider: expediente.cloudProvider, apiUrl: options.apiUrl });
    if (pre.verdict === 'SKIP') throw new Error(`retry checkout preflight failed: ${pre.reasons.join('; ')}`);
    // The work dir must be the execution directory, not the attempt directory.
    // Attempt directories are deleted by cleanup, so writing raw tool evidence
    // and CodeQL databases there loses the very artifacts a reviewer needs to
    // audit a retried run.  The checkout itself is still isolated under the
    // attempt dir via workspace.path.
    const ctx = makeContext(workspace.path, root, pre, options);
    // Routing targets are now recorded relative to the repository, so a retry
    // into a different worktree needs no rewriting at all.  rebaseTargets is kept
    // for executions persisted by older versions, which stored absolute paths
    // against a worktree that cleanup has since removed; without it those targets
    // fail validation and the retry reports a scan that never happened.
    const retriedRoute = Object.assign({}, expediente.signalRouting, {
      targets: rebaseTargets(expediente.signalRouting.targets, contained(root, 'worktree'), workspace.path),
      targetEntries: (expediente.signalRouting.targetEntries || []).map((entry) => Object.assign({}, entry, {
        target: relTarget(workspace.path, resolveTarget(workspace.path, entry.target)) || entry.target,
      })),
    });
    const stage = await runSpecialistStage(workspace.path, ctx, retriedRoute, Object.assign({}, options, { only: requested }), `${expediente.executionId}:${attemptId}`);
    // The stage emits a SKIPPED placeholder for every routed tool that was not
    // selected.  A retry must only overwrite the tools it actually re-ran:
    // assigning the whole results map would replace a good PARTIAL envelope
    // with a SKIPPED one and silently destroy evidence the retry never touched.
    for (const tool of requested) {
      if (stage.results[tool]) expediente.tools[tool] = stage.results[tool];
    }
    // Replace the record for a retried tool instead of appending a second one,
    // and never keep the stage's SKIPPED placeholders for untouched tools.
    const retried = new Set(requested);
    const freshRecords = stage.jobs.filter((job) => retried.has(job.tool));
    expediente.specialistJobs = [...(expediente.specialistJobs || []).filter((job) => !retried.has(job.tool)), ...freshRecords];
    expediente.resourceMetrics = { limits: { maxHeavy: options.maxHeavy || ctx.policies.resources.maxHeavy, maxLight: options.maxLight || ctx.policies.resources.maxLight }, scheduler: stage.scheduler };
    // specialist-jobs.json is the per-tool evidence file a reviewer reads first.
    // Leaving the pre-retry content in place makes the execution directory
    // contradict its own expediente.
    writeJson(contained(root, 'specialist-jobs.json'), expediente.specialistJobs, { overwrite: true });
    const stages = expediente.stages && typeof expediente.stages === 'object' ? expediente.stages : {};
    markStage(root, stages, 'SPECIALISTS', 'COMPLETE', { jobs: stage.jobs.length, attemptId, retriedTools: requested });
    expediente.stages = stages;
    expediente.specialistAttempts = [...(expediente.specialistAttempts || []), { attemptId, selectedTools: requested, jobs: stage.jobs, at: now() }];
    // Persist normalized findings into the execution directory, and only for the
    // tools this retry actually ran.  Writing every entry of stage.results would
    // also write the SKIPPED placeholders and replace a good findings file with
    // an empty array for a tool that was never retried.
    for (const tool of requested) {
      if (stage.results[tool]) writeJson(contained(root, 'specialists', tool, 'normalized.json'), stage.results[tool].findings || [], { overwrite: true });
    }
    const { policies } = loadConfig();
    const correlationFailure = applyCorrelation(expediente, Object.values(expediente.tools), workspace.path, policies, root);
    updateAuditVerdict(expediente, Object.values(expediente.tools), correlationFailure);
    expediente.pipelineStatus = 'RESUMED';
    return { executionDir: root, expediente, exitCode: exitCodeFor(expediente), attemptDir };
  } finally {
    const cleanup = cleanupManagedCheckout(attemptDir, { keepWorktree: !!options.keepWorktree });
    expediente.retryCleanup = [...(expediente.retryCleanup || []), { attemptId, ...cleanup }];
    safeWriteExecution(root, expediente);
    manifest(root, { pipelineStatus: expediente.pipelineStatus, resumed: true, retryCleanup: cleanup.cleanupStatus });
  }
}

module.exports = { runAuditV1, rerenderExecution, rerouteExecution, cleanupExecution, continueSpecialists, loadExecution, exitCodeFor, routeWithTargets, runSpecialistStage };
