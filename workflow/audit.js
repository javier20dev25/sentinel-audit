'use strict';
/**
 * The pipeline: preflight -> local Sentinel Cloud engine -> signal-routed specialists.
 *
 * The incremental shape is the point. Sentinel runs first and produces a
 * shortlist; only specialists justified by signal type and language are opened.
 */
const fs = require('fs');
const path = require('path');
const { STATUS, loadConfig, run, which, expand, gitOut, dirBytes } = require('../lib/core');
const A = require('../adapters');
const { correlate, auditVerdict, openCandidates, STATE, adjudicate } = require('../correlate');
const { preflight } = require('./preflight');

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
  const workDir = path.join(__dirname, '..', 'out', slug);
  fs.mkdirSync(workDir, { recursive: true });

  const expediente = {
    schema: 'sentinel-audit-expediente/1.0.0',
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

  if (pre.verdict === 'SKIP') {
    expediente.skipped = true;
    expediente.skipReasons = pre.reasons;
    fs.writeFileSync(path.join(workDir, 'expediente.json'), JSON.stringify(expediente, null, 2));
    return { expediente, workDir, pre };
  }

  const ctx = makeCtx(root, pre.inv, pre, workDir, opts);
  const TOOL_NAMES = ['sentinel', 'codeql', 'semgrep', 'bandit', 'shellcheck', 'trivy', 'osv'];
  const versions = {};
  for (const n of TOOL_NAMES) versions[n] = toolVersion(n, ctx.tools, pre);
  expediente.toolVersions = versions;

  // ---- track 1: cheap breadth. Sentinel first, always. ----
  const sen = await A.sentinel(root, ctx); ctx.charge('sentinel', sen.cost.wallClockMs);
  sen.version = versions.sentinel;
  expediente.tools.sentinel = sen;

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
  const routePlan = buildRoutePlan(actionableFindings, sen.status);
  expediente.signalRouting = routePlan;

  // ---- signal-routed specialist checks ----
  const envs = [sen];
  const push = (name, fn, o) => {
    const e = fn(root, ctx, o); ctx.charge(name, e.cost.wallClockMs);
    e.version = e.version || versions[name] || null;
    envs.push(e); expediente.tools[name] = e;
    process.stderr.write(`   ${name.padEnd(12)} ${e.status.padEnd(11)} ${String(e.findingCount).padStart(5)} signals  ${e.verdict}\n`);
    return e;
  };
  process.stderr.write(`\n== ${pre.name} (${pre.verdict})\n`);
  process.stderr.write(`   sentinel    ${sen.status.padEnd(11)} ${String(sen.findingCount).padStart(5)} signals  ${sen.verdict}\n`);
  process.stderr.write(`   route       ${routePlan.decision}  (${routePlan.reason})\n`);

  const sourceTools = ['codeql', 'semgrep', 'bandit', 'shellcheck'];
  for (const t of sourceTools) {
    const requested = opts.forceEtapaB || routePlan.tools.includes(t);
    if (!requested) {
      push(t, () => notApplicableLike(t, routePlan.decision === 'NO_ACTIONABLE_SENTINEL_FINDINGS'
        ? 'NO_ACTIONABLE_SENTINEL_FINDINGS: no source specialist was justified by Sentinel Cloud'
        : `not routed: ${routePlan.reason}`));
    } else if (opts.skipSpecialists) {
      push(t, () => emptyLike(t));
    } else if (t === 'codeql') {
      push(t, A.codeql, { language: pre.inv.mainLanguage, ram: pre.cost.requiredRamMB });
    } else if (t === 'semgrep') {
      push(t, A.semgrep, { scope: shortlist, maxTargets: opts.maxScopeFiles || 25 });
    } else if (t === 'bandit') {
      push(t, A.bandit, { scope: shortlist, maxTargets: opts.maxScopeFiles || 50 });
    } else {
      push(t, A.shellcheck, { scope: shortlist, maxTargets: opts.maxScopeFiles || 50 });
    }
  }
  for (const t of ['trivy', 'osv']) {
    if (!routePlan.tools.includes(t)) {
      push(t, () => notApplicableLike(t, 'no Sentinel Cloud dependency/SCA signal justified this tool'));
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
  expediente.finishedAt = new Date().toISOString();
  expediente.totalWallClockMs = Date.now() - t0;
  expediente.artifactBytes = dirBytes(workDir);

  fs.writeFileSync(path.join(workDir, 'expediente.json'), JSON.stringify(expediente, null, 2));
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

function buildRoutePlan(findings, sentinelStatus) {
  const actionable = Array.isArray(findings) ? findings.filter((f) => f.signalClass === 'ACTIONABLE_SIGNAL') : [];
  const engineIncomplete = sentinelStatus === 'ERROR';
  const categories = [...new Set(actionable.map((f) => f.category).filter(Boolean))].sort();
  const files = [...new Set(actionable.map((f) => f.file).filter(Boolean))].sort();
  const tools = new Set();
  if (categories.some((c) => ['process', 'network', 'filesystem'].includes(c))) {
    tools.add('codeql'); tools.add('semgrep');
  }
  if (categories.includes('secret')) tools.add('semgrep');
  if (categories.includes('lifecycle')) { tools.add('semgrep'); tools.add('trivy'); }
  if (categories.includes('dependency')) { tools.add('trivy'); tools.add('osv'); }
  if (categories.some((c) => ['process', 'network', 'filesystem'].includes(c))) {
    if (files.some((f) => /\.pyi?$/i.test(f))) tools.add('bandit');
    if (files.some((f) => /\.(?:sh|bash|zsh)$/i.test(f))) tools.add('shellcheck');
  }
  const orderedTools = ['codeql', 'semgrep', 'bandit', 'shellcheck', 'trivy', 'osv'].filter((t) => tools.has(t));
  return {
    decision: engineIncomplete
      ? 'SENTINEL_ENGINE_INCOMPLETE'
      : actionable.length ? (orderedTools.length ? 'AMPLIFY' : 'OBSERVE') : 'NO_ACTIONABLE_SENTINEL_FINDINGS',
    reason: engineIncomplete
      ? `Sentinel Cloud did not complete (status ${sentinelStatus}); Etapa A produced no usable signal set and absence of findings is not evidence of absence`
      : actionable.length
        ? `Sentinel Cloud emitted ${actionable.length} actionable signal(s) in ${categories.join(', ') || 'unrouted categories'}`
        : 'Etapa A emitted no actionable Sentinel Cloud signal; no secondary tools are justified',
    engineIncomplete, signalCount: actionable.length, categories, files, tools: orderedTools,
  };
}

module.exports.buildRoutePlan = buildRoutePlan;
