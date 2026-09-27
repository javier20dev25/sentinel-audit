'use strict';
/**
 * The pipeline: preflight -> Sentinel (breadth) -> focused Purple -> specialists.
 *
 * The incremental shape is the point. Sentinel runs first and produces a
 * shortlist; Purple and the expensive verifiers are focused on that shortlist
 * instead of walking an entire monorepo. SCA runs as a cheap parallel track.
 */
const fs = require('fs');
const path = require('path');
const { STATUS, loadConfig, run, gitOut, dirBytes } = require('../lib/core');
const A = require('../adapters');
const { correlate, auditVerdict, STATE, adjudicate } = require('../correlate');
const { preflight } = require('./preflight');

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

function audit(repoPath, opts = {}) {
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

  // ---- track 1: cheap breadth. Sentinel first, always. ----
  const sen = A.sentinel(root, ctx); ctx.charge('sentinel', sen.cost.wallClockMs);
  expediente.tools.sentinel = sen;

  // ---- shortlist from Sentinel; fall back to production files if it is silent ----
  let shortlist = [...new Set(sen.findings.map((f) => f.file).filter(Boolean))];
  let shortlistOrigin = 'sentinel';
  if (!shortlist.length) {
    shortlistOrigin = 'fallback:no-sentinel-signal';
    const take = opts.maxScopeFiles || 40;
    const walk = (d, depth) => {
      if (shortlist.length >= take || depth > 10) return;
      let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
      for (const e of ents) {
        if (shortlist.length >= take) return;
        if (['node_modules', '.git', 'dist', 'build', '.next', 'vendor', 'test', 'tests', '__tests__', 'examples'].includes(e.name)) continue;
        const f = path.join(d, e.name);
        if (e.isDirectory()) walk(f, depth + 1);
        else if (/\.(ts|tsx|js|jsx|mjs|cjs|py|go|java|rb|php)$/.test(e.name)) shortlist.push(f);
      }
    };
    walk(root, 0);
  }
  expediente.shortlist = { origin: shortlistOrigin, count: shortlist.length };

  // ---- track 2: attack hypothesis, focused ----
  const pur = A.purple(root, ctx, { scope: opts.purpleFull ? null : shortlist });
  ctx.charge('purple', pur.cost.wallClockMs);
  expediente.tools.purple = pur;

  // ---- track 3: the verifiers ----
  const envs = [sen, pur];
  const push = (name, fn, o) => {
    const e = fn(root, ctx, o); ctx.charge(name, e.cost.wallClockMs); envs.push(e); expediente.tools[name] = e;
    process.stderr.write(`   ${name.padEnd(12)} ${e.status.padEnd(11)} ${String(e.findingCount).padStart(5)} signals  ${e.verdict}\n`);
    return e;
  };
  process.stderr.write(`\n== ${pre.name} (${pre.verdict})\n`);
  process.stderr.write(`   sentinel    ${sen.status.padEnd(11)} ${String(sen.findingCount).padStart(5)} signals  ${sen.verdict}\n`);
  process.stderr.write(`   purple      ${pur.status.padEnd(11)} ${String(pur.findingCount).padStart(5)} signals  ${pur.verdict}  (scope: ${shortlistOrigin})\n`);

  if (opts.skipSpecialists) {
    // Skips every source analyser, but NOT SCA: the cheap track still runs, and
    // each skip is recorded as SKIPPED so the verdict stays honest.
    for (const t of ['codeql', 'semgrep', 'bandit', 'shellcheck']) push(t, () => emptyLike(t));
  } else {
    push('codeql', A.codeql, { language: pre.inv.mainLanguage, ram: pre.cost.requiredRamMB });
    push('semgrep', A.semgrep, { scope: opts.purpleFull ? null : shortlist, maxTargets: opts.maxScopeFiles || 25 });
    push('bandit', A.bandit);
    push('shellcheck', A.shellcheck);
  }
  // ---- track 4: cheap parallel SCA/secrets ----
  push('trivy', A.trivy);
  push('osv', A.osv);

  // ---- correlate ----
  const { candidates, observations, nonProductionSignals } = correlate(root, envs, policies);
  // Seal the immutable identity of the target onto every record, so a candidate
  // read three days from now still states which commit it came from.
  for (const c of [candidates, observations]) for (const r of c) {
    r.commit = pre.commit; r.tree = pre.tree; r.license = pre.license ? pre.license.file : null;
  }
  expediente.candidates = candidates;
  expediente.observations = observations;
  expediente.nonProductionSignals = nonProductionSignals.slice(0, 200);
  expediente.auditVerdict = auditVerdict(envs, candidates);
  expediente.finishedAt = new Date().toISOString();
  expediente.totalWallClockMs = Date.now() - t0;
  expediente.artifactBytes = dirBytes(workDir);

  fs.writeFileSync(path.join(workDir, 'expediente.json'), JSON.stringify(expediente, null, 2));
  return { expediente, workDir, pre, shortlist };
}

const emptyLike = (tool) => ({
  tool, status: STATUS.SKIPPED, verdict: 'SKIPPED', findings: [], findingCount: 0, notApplicable: false,
  coverage: { analysisCompleted: false, errors: ['skipped by request'] },
  cost: { wallClockMs: 0, timedOut: false }, notes: ['skipped via --skip-specialists'], error: null, rawArtifact: null,
});

module.exports = { audit, makeCtx };
