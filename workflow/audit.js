'use strict';
/**
 * The pipeline: preflight -> local Sentinel Cloud engine -> signal-routed specialists.
 *
 * The incremental shape is the point. Sentinel runs first and produces a
 * shortlist; only specialists justified by signal type and language are opened.
 */
const fs = require('fs');
const path = require('path');
const { STATUS, loadConfig, run, which, expand, gitOut, dirBytes, EXT_LANG } = require('../lib/core');
const A = require('../adapters');
const { correlate, auditVerdict, openCandidates, STATE, adjudicate } = require('../correlate');
const { preflight } = require('./preflight');
// Aliased: a local `abs` binding already exists further down in audit(), and a
// shadowed import would silently become a string instead of a function.
const { abs: resolveTarget, relTarget } = require('./paths');
const { buildIdentity } = require('./identity');
const { renderReport } = require('../reports/expediente');
const crypto = require('crypto');

/**
 * A finding is only reproducible if you know which tool produced it. Every
 * envelope carries the resolved version, and the vendored engine is identified
 * by its commit rather than a version string it does not publish.
 */
function toolVersion(name, tools, pre) {
  if (name === 'sentinel') return pre && pre.health && pre.health.sentinel && pre.health.sentinel.engineId || null;
  const cfg = tools[name];
  if (!cfg || !cfg.bin) return null;
  // The configured path may carry %LOCALAPPDATA%/%USERPROFILE%, so it has to be
  // expanded before it is spawned. Passing the raw template silently yields a
  // null version for every tool that is not a bare PATH lookup.
  const bin = expand(cfg.bin);
  const w = which(bin);
  return w.available ? (w.version || 'unknown') : null;
}

function makeCtx(repoRoot, inv, pre, workDir, opts = {}) {
  const { tools, policies } = loadConfig();
  const spent = {};
  return {
    tools, policies, inv, pre, work: workDir,
    keepDb: !!opts.keepDb,
    /** Remaining budget for a tool, in ms. Never returns "unbounded". */
    budget(tool) {
      const capMin = policies.budget.perToolMinutes[tool] || 5;
      const totalCap = policies.budget.totalWallClockMinutes;
      const used = Object.values(spent).reduce((a, b) => a + b, 0) / 60000;
      const remainingTotal = Math.max(0, totalCap - used);
      const remainingTool = Math.max(0, capMin - (spent[tool] || 0) / 60000);
      return Math.max(30, Math.min(remainingTool, remainingTotal, capMin) * 60 * 1000);
    },
    charge(tool, ms) { spent[tool] = (spent[tool] || 0) + (ms || 0); },
  };
}

async function audit(repoPath, opts = {}) {
  const t0 = Date.now();
  const { policies } = loadConfig();
  const pre = preflight(repoPath, opts);
  const root = pre.repo;
  const slug = (opts.name || path.basename(root)).replace(/[^\w.-]+/g, '_');
  const executionId = `exec-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomUUID()}`;
  const workDir = path.join(__dirname, '..', 'out', slug, executionId);
  fs.mkdirSync(workDir, { recursive: true });
  for (const d of ['cloud', 'routing', 'correlation', 'report']) fs.mkdirSync(path.join(workDir, d), { recursive: true });

  const expediente = {
    schema: 'sentinel-audit-expediente/1.0.0',
    executionId,
    artifactDir: workDir,
    name: pre.name,
    repo: root,
    commit: pre.commit, tree: pre.tree, shallow: pre.shallow,
    startedAt: new Date().toISOString(),
    preflight: {
      verdict: pre.verdict, reasons: pre.reasons, limits: pre.limits,
      disclosure: pre.disclosure, license: pre.license,
      trackedFileCount: pre.trackedFileCount,
      languages: pre.inv && pre.inv.languages,
      productionFiles: pre.inv && pre.inv.production, nonShippedRatio: pre.inv && pre.inv.nonShippedRatio,
      estimatedMinutes: pre.cost && pre.cost.totalEstimateMinutes,
      requiredRamMB: pre.cost && pre.cost.requiredRamMB,
      largeRepo: pre.cost && pre.cost.largeRepo,
      toolHealth: pre.health,
    },
    tools: {},
    candidates: [],
    nonProductionSignals: [],
    auditVerdict: null,
    localChanges: { branch: null, commit: null, patch: null },
    drafts: [],
    publication: loadConfig().policies.publication,
  };

  const toolNamesForIdentity = ['sentinel', 'codeql', 'semgrep', 'bandit', 'shellcheck', 'trivy', 'osv'];
  const identityVersions = {};
  for (const n of toolNamesForIdentity) identityVersions[n] = toolVersion(n, loadConfig().tools, pre);
  expediente.toolVersions = identityVersions;
  expediente.identity = buildIdentity({ executionId, repo: root, preflight: pre, tools: identityVersions, startedAt: expediente.startedAt });
  fs.writeFileSync(path.join(workDir, 'identity.json'), JSON.stringify(expediente.identity, null, 2), { flag: 'wx' });

  if (pre.verdict === 'SKIP') {
    expediente.skipped = true;
    expediente.skipReasons = pre.reasons;
    fs.writeFileSync(path.join(workDir, 'expediente.json'), JSON.stringify(expediente, null, 2));
    fs.writeFileSync(path.join(workDir, 'REPORT.json'), JSON.stringify(expediente, null, 2), { flag: 'wx' });
    fs.writeFileSync(path.join(workDir, 'report', 'REPORT.md'), `# Sentinel Audit — PREFLIGHT FAILED\n\n- Repository: \`${root}\`\n- Commit: \`${pre.commit || 'unknown'}\`\n- Reason: ${pre.reasons.join('; ')}\n\nNo scan was run.\n`, { flag: 'wx' });
    return { expediente, workDir, pre };
  }

  const ctx = makeCtx(root, pre.inv, pre, workDir, opts);
  const TOOL_NAMES = ['sentinel', 'codeql', 'semgrep', 'bandit', 'shellcheck', 'trivy', 'osv'];
  const versions = identityVersions;
  expediente.toolVersions = versions;

  // ---- track 1: cheap breadth. Sentinel first, always. ----
  const sen = await A.sentinel(root, ctx); ctx.charge('sentinel', sen.cost.wallClockMs);
  sen.version = versions.sentinel;
  expediente.tools.sentinel = sen;
  fs.writeFileSync(path.join(workDir, 'cloud', 'normalized.json'), JSON.stringify(sen.findings, null, 2), { flag: 'wx' });

  // ---- Etapa A -> Etapa B gate ----
  // Only an ACTIONABLE_SIGNAL may open a file to an expensive lens. A lone
  // `import` or string-literal observation is inventory, not a lead, and using
  // it as a shortlist is what previously dragged entire repositories into
  // CodeQL and reported the resulting volume as unverified security issues.
  const actionableFindings = sen.findings.filter((f) => f.signalClass === 'ACTIONABLE_SIGNAL');
  let shortlist = [...new Set(actionableFindings.map((f) => f.file).filter(Boolean))];
  let shortlistOrigin = 'sentinel:actionable-signal';
  if (!shortlist.length) {
    shortlistOrigin = 'none:no-actionable-sentinel-signal';
  }
  expediente.shortlist = {
    origin: shortlistOrigin,
    count: shortlist.length,
    // The promoted file list, relative to the target. Without it a reader can
    // see that two files were promoted but not which, so "promoted to Etapa B"
    // cannot be checked against "rejected before Etapa B".
    files: shortlist.map((f) => path.relative(root, f).split(path.sep).join('/')),
    sentinelTotal: sen.findings.length,
    sentinelActionable: actionableFindings.length,
    sentinelObservationOnly: sen.findings.length - actionableFindings.length,
  };
  const routingMode = opts.routingMode || policies.routing.defaultMode;
  const routePlan = buildRoutePlan(actionableFindings, sen.status, routingMode, root, sen.coverage, policies.routing.signalToolMap);
  routePlan.executionId = executionId;
  routePlan.engineExecutionComplete = !routePlan.engineIncomplete;
  routePlan.coverageKnown = !!(sen.coverage && sen.coverage.coverageKnown);
  routePlan.coverageUnknown = !routePlan.coverageKnown;
  routePlan.filesScanned = sen.coverage && Number.isInteger(sen.coverage.filesScanned) ? sen.coverage.filesScanned : null;
  routePlan.filesFailed = sen.coverage && Number.isInteger(sen.coverage.filesFailed) ? sen.coverage.filesFailed : null;
  routePlan.alertsFailed = sen.coverage && Number.isInteger(sen.coverage.alertsFailed) ? sen.coverage.alertsFailed : null;
  const sourcePaths = (pre.trackedFiles || []).filter((rel) => !!EXT_LANG[path.extname(rel).toLowerCase()]);
  const selectedTargets = routePlan.targets.map((p) => resolveTarget(root, p)).filter(Boolean);
  const skipDirs = new Set(policies.coverage.skipDirs.map((x) => x.toLowerCase()));
  const fileDisposition = sourcePaths.map((rel) => {
    const abs = path.resolve(root, rel);
    const excludedDir = rel.split(/[\\/]/).some((segment) => skipDirs.has(segment.toLowerCase()));
    const selected = routingMode === 'repo' ? true : routingMode === 'directory'
      ? selectedTargets.some((target) => abs === target || abs.startsWith(target + path.sep))
      : selectedTargets.includes(abs);
    return { file: rel, selected: selected && !excludedDir, reason: excludedDir ? 'excluded by configured analysis skipDirs' : selected ? 'selected by Cloud promotion at configured routing granularity' : 'not promoted for this stage; not a safety judgment' };
  });
  routePlan.filesSelected = fileDisposition.filter((x) => x.selected).length;
  routePlan.filesExcludedCount = fileDisposition.filter((x) => !x.selected).length;
  routePlan.filesExcluded = fileDisposition.filter((x) => !x.selected);
  routePlan.fileSelection = fileDisposition;
  expediente.signalRouting = routePlan;
  fs.writeFileSync(path.join(workDir, 'routing', 'decisions.json'), JSON.stringify(routePlan, null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(workDir, 'routing', 'targets.json'), JSON.stringify({ mode: routingMode, targets: routePlan.targets, targetCount: routePlan.targets.length, filesSelected: routePlan.filesSelected, filesExcludedCount: routePlan.filesExcludedCount, fileSelection: routePlan.fileSelection, promotions: routePlan.promotions }, null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(workDir, 'shortlist.json'), JSON.stringify(expediente.shortlist, null, 2), { flag: 'wx' });

  // ---- signal-routed specialist checks ----
  const envs = [sen];
  const specialistJobs = [];
  const push = (name, fn, o) => {
    const routed = routePlan.tools.includes(name);
    const jobId = `${executionId}:${name}`;
    let e;
    try { e = fn(root, ctx, o); }
    catch (error) {
      e = { tool: name, status: STATUS.ERROR, verdict: 'TOOL_ERROR', notApplicable: false, findings: [], findingCount: 0,
        coverage: { filesSeen: null, filesEligible: null, filesParsed: null, analysisCompleted: false, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: [`adapter threw: ${error.message}`] },
        cost: { wallClockMs: 0, timedOut: false }, notes: ['adapter failure isolated; other specialists continue'], rawArtifact: null, error: error.message };
    }
    if (!e.cost) e.cost = { wallClockMs: 0, timedOut: false };
    if (!Array.isArray(e.findings)) e.findings = [];
    ctx.charge(name, e.cost.wallClockMs);
    e.version = e.version || versions[name] || null;
    e.jobId = jobId;
    e.scopeMode = name === 'codeql' || name === 'trivy' || name === 'osv' ? 'REPOSITORY' : routingMode;
    e.findings = (e.findings || []).map((finding, index) => ({
      ...finding,
      specialistFindingId: 'SF-' + crypto.createHash('sha256').update(JSON.stringify([jobId, finding.rule || finding.kind, finding.file || '', finding.line || null, index])).digest('hex').slice(0, 16),
      jobId,
      promotionIds: promotionIdsForFinding(finding, routePlan, e.scopeMode, root),
    }));
    envs.push(e); expediente.tools[name] = e;
    const requested = (routed || opts.forceEtapaB) && !manuallyOmitted(name) && !opts.skipSpecialists;
    specialistJobs.push({ jobId, tool: name, routed, requested, executed: !e.notApplicable && e.status !== STATUS.SKIPPED, status: e.status, version: e.version, scopeMode: e.scopeMode, targets: requested ? (e.scopeMode === 'REPOSITORY' ? [root] : routePlan.targets) : [], promotionIds: requested && e.scopeMode !== 'REPOSITORY' ? routePlan.promotions.map((p) => p.promotionId) : [], routingRelation: e.scopeMode === 'REPOSITORY' ? 'repo-level specialist; execution is not limited by Cloud promotions' : 'targets derived from Cloud promotion', findingCount: e.findingCount, durationMs: e.cost && e.cost.wallClockMs || 0, timedOut: !!(e.cost && e.cost.timedOut), rawArtifact: e.rawArtifact, error: e.error });
    process.stderr.write(`   ${name.padEnd(12)} ${e.status.padEnd(11)} ${String(e.findingCount).padStart(5)} signals  ${e.verdict}\n`);
    return e;
  };
  process.stderr.write(`\n== ${pre.name} (${pre.verdict})\n`);
  process.stderr.write(`   sentinel    ${sen.status.padEnd(11)} ${String(sen.findingCount).padStart(5)} signals  ${sen.verdict}\n`);
  process.stderr.write(`   route       ${routePlan.decision}  (${routePlan.reason})\n`);

  const maxTargets = Number.isInteger(opts.maxScopeFiles) && opts.maxScopeFiles > 0
    ? opts.maxScopeFiles : (Number.isInteger(policies.routing.maxTargets) && policies.routing.maxTargets > 0 ? policies.routing.maxTargets : null);
  const onlyTools = opts.onlyTools && opts.onlyTools.length ? new Set(opts.onlyTools) : null;
  const skippedTools = new Set(opts.skipTools || []);
  const invalidOnly = onlyTools ? [...onlyTools].filter((tool) => !routePlan.tools.includes(tool)) : [];
  const invalidSkip = [...skippedTools].filter((tool) => !['codeql', 'semgrep', 'bandit', 'shellcheck', 'trivy', 'osv'].includes(tool));
  if (invalidOnly.length || invalidSkip.length) throw new Error(`invalid specialist selection; unrouted --only: ${invalidOnly.join(', ') || 'none'}; unknown --skip: ${invalidSkip.join(', ') || 'none'}`);
  const manuallyOmitted = (tool) => skippedTools.has(tool) || (!!onlyTools && !onlyTools.has(tool));
  const sourceTools = ['codeql', 'semgrep', 'bandit', 'shellcheck'];
  for (const t of sourceTools) {
    const requested = opts.forceEtapaB || routePlan.tools.includes(t);
    if (!requested) {
      push(t, () => notApplicableLike(t, routePlan.decision === 'NO_ACTIONABLE_SENTINEL_FINDINGS'
        ? 'NO_ACTIONABLE_SENTINEL_FINDINGS: no source specialist was justified by Sentinel Cloud'
        : `not routed: ${routePlan.reason}`));
    } else if (manuallyOmitted(t)) {
      push(t, () => emptyLike(t));
    } else if (opts.skipSpecialists) {
      push(t, () => emptyLike(t));
    } else if (t === 'codeql') {
      push(t, A.codeql, { language: pre.inv.mainLanguage, ram: pre.cost.requiredRamMB });
    } else if (t === 'semgrep') {
      push(t, A.semgrep, { scope: routePlan.targets, maxTargets });
    } else if (t === 'bandit') {
      push(t, A.bandit, { scope: routePlan.targets, maxTargets });
    } else {
      push(t, A.shellcheck, { scope: routePlan.targets, maxTargets });
    }
  }
  for (const t of ['trivy', 'osv']) {
    if (!routePlan.tools.includes(t)) {
      push(t, () => notApplicableLike(t, 'no Sentinel Cloud dependency/SCA signal justified this tool'));
    } else if (manuallyOmitted(t)) {
      push(t, () => emptyLike(t));
    } else if (opts.skipSpecialists) {
      push(t, () => emptyLike(t));
    } else {
      push(t, A[t]);
    }
  }

  // ---- correlate ----
  const { candidates, observations, nonProductionSignals } = correlate(root, envs, policies);
  // Seal the immutable identity of the target onto every record, so a candidate
  // read three days from now still states which commit it came from.
  for (const c of [candidates, observations]) for (const r of c) {
    r.commit = pre.commit; r.tree = pre.tree; r.license = pre.license ? pre.license.file : null;
  }
  expediente.candidates = candidates;
  expediente.observations = observations;
  const NONPROD_CAP = 200;
  expediente.nonProductionTotal = nonProductionSignals.length;
  expediente.nonProductionTruncated = nonProductionSignals.length > NONPROD_CAP;
  expediente.nonProductionSignals = nonProductionSignals.slice(0, NONPROD_CAP);
  if (expediente.nonProductionTruncated) {
    expediente.nonProductionFullArtifact = path.join(workDir, 'non-production-signals.json');
    fs.writeFileSync(expediente.nonProductionFullArtifact, JSON.stringify(nonProductionSignals, null, 2));
  }
  expediente.auditVerdict = auditVerdict(envs, openCandidates(candidates));
  for (const [tool, result] of Object.entries(expediente.tools)) {
    if (tool === 'sentinel') continue;
    const normalized = path.join(workDir, 'specialists', tool, 'normalized', 'findings.json');
    fs.mkdirSync(path.dirname(normalized), { recursive: true });
    fs.writeFileSync(normalized, JSON.stringify(result.findings || [], null, 2), { flag: 'wx' });
  }
  fs.writeFileSync(path.join(workDir, 'correlation', 'findings.json'), JSON.stringify(envs.flatMap((e) => (e.findings || []).map((f) => ({ ...f, tool: e.tool }))), null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(workDir, 'correlation', 'candidates.json'), JSON.stringify(candidates, null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(workDir, 'correlation', 'candidate-ledger.json'), JSON.stringify(candidates, null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(workDir, 'specialist-jobs.json'), JSON.stringify(specialistJobs, null, 2), { flag: 'wx' });
  const cleanupErrors = Object.entries(expediente.tools).filter(([, result]) => result.cleanupError).map(([tool, result]) => `${tool}: ${result.cleanupError}`);
  const cleanup = { cleanupStatus: cleanupErrors.length ? 'FAILED' : 'SUCCESS', cleanupErrors, removed: [], retainedEvidence: true, note: 'The runner scans the supplied checkout in place; it created no clone. Tool-specific temporary cleanup is recorded in each tool envelope.' };
  expediente.cleanup = cleanup;
  expediente.finishedAt = new Date().toISOString();
  expediente.totalWallClockMs = Date.now() - t0;
  expediente.artifactBytes = dirBytes(workDir);

  fs.writeFileSync(path.join(workDir, 'cleanup.json'), JSON.stringify(cleanup, null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(workDir, 'expediente.json'), JSON.stringify(expediente, null, 2));
  fs.writeFileSync(path.join(workDir, 'report', 'REPORT.json'), JSON.stringify(expediente, null, 2), { flag: 'wx' });
  renderReport(expediente);
  return { expediente, workDir, pre, shortlist };
}

/**
 * A tool that was deliberately not used, as distinct from one that failed.
 * `notApplicable` is what keeps it out of `required` and `degraded` in
 * auditVerdict, so opting out states the decision in the expediente instead of
 * silently degrading the run. Same shape the bandit and shellcheck adapters
 * already return when a target has no Python or no shell.
 */
const notApplicableLike = (tool, note) => ({
  tool, status: STATUS.SKIPPED, verdict: 'NOT_APPLICABLE', findings: [], findingCount: 0, notApplicable: true,
  coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true, errors: [] },
  cost: { wallClockMs: 0, timedOut: false }, notes: [note], error: null, rawArtifact: null,
});

const emptyLike = (tool) => ({
  tool, status: STATUS.SKIPPED, verdict: 'SKIPPED', findings: [], findingCount: 0, notApplicable: false,
  coverage: { analysisCompleted: false, errors: ['skipped by request'] },
  cost: { wallClockMs: 0, timedOut: false }, notes: ['skipped via --skip-specialists'], error: null, rawArtifact: null,
});

module.exports = { audit, makeCtx };

function buildRoutePlan(findings, sentinelStatus, mode = 'file', repoRoot = null, coverage = {}, signalToolMap = {}) {
  const actionable = Array.isArray(findings) ? findings.filter((f) => f.signalClass === 'ACTIONABLE_SIGNAL') : [];
  const engineIncomplete = sentinelStatus === 'ERROR' || sentinelStatus === 'UNSUPPORTED'
    || coverage.engineExecutionComplete === false || coverage.engineIncomplete === true
    || (Number.isInteger(coverage.filesFailed) && coverage.filesFailed > 0)
    || (Number.isInteger(coverage.alertsFailed) && coverage.alertsFailed > 0)
    || (Number.isInteger(coverage.alertsEnrichFailed) && coverage.alertsEnrichFailed > 0);
  const categories = [...new Set(actionable.map((f) => f.category).filter(Boolean))].sort();
  const files = [...new Set(actionable.map((f) => f.file).filter(Boolean))].sort();
  const normalizedMode = ['file', 'directory', 'repo'].includes(mode) ? mode : 'file';
  const promotionByTarget = new Map();
  const rootAbsolute = repoRoot ? path.resolve(repoRoot) : null;
  const directoryFor = (file) => {
    const directory = path.dirname(file);
    // This is deliberate policy, not an accidental path.dirname side effect:
    // a root-level signal chooses the repository root only in directory mode,
    // and the promotion record makes that expansion auditable.
    return rootAbsolute && directory === rootAbsolute ? rootAbsolute : directory;
  };
  const targets = normalizedMode === 'repo'
    ? (repoRoot ? ['.'] : [])
    : normalizedMode === 'directory'
      ? [...new Set(files.map(directoryFor))].sort()
      : files;
  // The persisted identity of a target is repository-relative.  Absolute paths
  // embed the execution directory, are meaningless once the disposable worktree
  // is cleaned up, and break retry the moment the next attempt rebuilds the
  // checkout somewhere else.  Internal bookkeeping below still needs the
  // absolute form, so it is derived once and kept out of the persisted plan.
  const asRelative = (target) => {
    if (!rootAbsolute) return path.resolve(target);
    const absolute = resolveTarget(rootAbsolute, target);
    // A target outside the repository keeps its absolute form: the specialists
    // reject it as out of scope, which is the accurate outcome, and inventing a
    // relative identity for it would hide the escape.
    return absolute ? relTarget(rootAbsolute, absolute) : path.resolve(target);
  };
  const relativeTargets = targets.map(asRelative);
  const promotions = targets.map((target, index) => {
    const identity = relativeTargets[index];
    const promotionId = 'PROM-' + crypto.createHash('sha256').update(`${normalizedMode}\0${identity}`).digest('hex').slice(0, 16);
    promotionByTarget.set(identity, promotionId);
    const signals = actionable.filter((f) => normalizedMode === 'repo'
      || (normalizedMode === 'directory' ? directoryFor(f.file) === target : f.file === target));
    return {
      promotionId, target: identity, mode: normalizedMode,
      reason: `promoted by ${signals.length} actionable Sentinel Cloud signal(s)`,
      signalIds: signals.map((s) => s.signalId).filter(Boolean),
      rootLevelExpansion: normalizedMode === 'directory' && rootAbsolute && path.resolve(target) === rootAbsolute,
      status: 'PROMOTED',
    };
  });
  for (const f of actionable) {
    const target = normalizedMode === 'repo' ? repoRoot : normalizedMode === 'directory' ? directoryFor(f.file) : f.file;
    f.promotionIds = promotions.filter((p) => p.target === asRelative(target)).map((p) => p.promotionId);
  }
  const tools = new Set();
  for (const category of categories) for (const tool of signalToolMap[category] || []) tools.add(tool);
  if (!Object.keys(signalToolMap).length && categories.some((c) => ['process', 'network', 'filesystem'].includes(c))) {
    tools.add('codeql'); tools.add('semgrep');
  }
  if (categories.some((c) => ['process', 'network', 'filesystem'].includes(c))) {
    if (files.some((f) => /\.pyi?$/i.test(f))) tools.add('bandit');
    if (files.some((f) => /\.(?:sh|bash|zsh)$/i.test(f))) tools.add('shellcheck');
  }
  const orderedTools = engineIncomplete ? [] : ['codeql', 'semgrep', 'bandit', 'shellcheck', 'trivy', 'osv'].filter((t) => tools.has(t));
  return {
    decision: engineIncomplete
      ? 'SENTINEL_ENGINE_INCOMPLETE'
      : actionable.length ? (orderedTools.length ? 'AMPLIFY' : 'OBSERVE') : 'NO_ACTIONABLE_SENTINEL_FINDINGS',
    reason: engineIncomplete
      ? `Sentinel Cloud did not complete (status ${sentinelStatus}); Etapa A produced no usable signal set and absence of findings is not evidence of absence`
      : actionable.length
        ? `Sentinel Cloud emitted ${actionable.length} actionable signal(s) in ${categories.join(', ') || 'unrouted categories'}`
        : 'Etapa A emitted no actionable Sentinel Cloud signal; no secondary tools are justified',
    engineIncomplete, engineExecutionComplete: !engineIncomplete,
    coverageKnown: !!coverage.coverageKnown, coverageUnknown: !coverage.coverageKnown,
    filesScanned: Number.isInteger(coverage.filesScanned) ? coverage.filesScanned : null,
    filesFailed: Number.isInteger(coverage.filesFailed) ? coverage.filesFailed : null,
    alertsFailed: Number.isInteger(coverage.alertsEnrichFailed) ? coverage.alertsEnrichFailed : Number.isInteger(coverage.alertsFailed) ? coverage.alertsFailed : null,
    signalCount: actionable.length, categories, files, mode: normalizedMode,
    targets: relativeTargets, targetCount: relativeTargets.length, promotions, excluded: [], filesSelected: normalizedMode === 'file' ? files.length : null,
    filesExcluded: [], exclusionReason: 'No Cloud-promoted actionable target was excluded by the router; unpromoted files were not selected, not declared safe.',
    tools: orderedTools,
  };
}

/**
 * A finding is associated with a promotion by target membership.  Targets are
 * persisted as repository-relative identities, so they have to be resolved
 * against the root of the current execution before being compared with the
 * absolute file path a tool reports.  Resolving them against the process cwd
 * instead would match nothing and silently drop every finding's routing
 * association, which is how a routed audit can look clean while scanning
 * nothing.
 */
function promotionIdsForFinding(finding, routePlan, scopeMode, root) {
  if (scopeMode === 'REPOSITORY') return [];
  const file = finding && finding.file ? path.resolve(finding.file) : null;
  if (!file) return [];
  const toAbsolute = (target) => (root ? resolveTarget(root, target) : path.resolve(target));
  const matches = (routePlan.promotions || []).filter((p) => p.mode === 'repo'
    || (p.mode === 'file' && toAbsolute(p.target) === file)
    || (p.mode === 'directory' && (file === toAbsolute(p.target) || file.startsWith(toAbsolute(p.target) + path.sep))));
  return matches.map((p) => p.promotionId);
}

module.exports.buildRoutePlan = buildRoutePlan;
module.exports.promotionIdsForFinding = promotionIdsForFinding;
