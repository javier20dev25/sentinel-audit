'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const A = require('../adapters');
const { preflight } = require('./preflight');
const { makeCtx, promotionIdsForFinding } = require('./audit');
const { correlate, auditVerdict, openCandidates } = require('../correlate');
const { renderReport } = require('../reports/expediente');
const { STATUS, loadConfig } = require('../lib/core');

function runSpecialists(executionDir, opts = {}) {
  const dir = path.resolve(executionDir);
  const file = path.join(dir, 'expediente.json');
  if (!fs.existsSync(file)) throw new Error('execution directory has no expediente.json');
  const e = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!e.executionId || !e.identity || !e.tools || !e.tools.sentinel || !e.signalRouting) throw new Error('saved run lacks identity, Cloud result, or route plan');
  const attempts = e.specialistAttempts || [];
  const completedTools = new Set(attempts.flatMap((attempt) => (attempt.jobs || []).map((job) => job.tool)));
  const repo = path.resolve(e.repo);
  const pre = preflight(repo, { commit: e.commit });
  if (pre.verdict === 'SKIP' || pre.commit !== e.commit || pre.tree !== e.tree || pre.workingTreeClean !== true) {
    throw new Error(`target identity/worktree gate failed: ${pre.reasons.join('; ') || 'commit/tree mismatch or dirty checkout'}`);
  }
  const routed = e.signalRouting.tools || [];
  const only = opts.only && opts.only.length ? [...new Set(opts.only)] : routed.filter((tool) => !completedTools.has(tool));
  const invalid = only.filter((tool) => !routed.includes(tool));
  if (invalid.length) throw new Error(`requested specialists are not justified by the saved Cloud route: ${invalid.join(', ')}`);
  const repeated = only.filter((tool) => completedTools.has(tool));
  if (repeated.length) throw new Error(`refusing to overwrite completed specialist evidence: ${repeated.join(', ')}`);
  if (!only.length) throw new Error('no routed specialists remain to execute');
  // Short id for the same Windows path-length reason as pipeline-v1.js.
  const attemptId = `specialist-${crypto.randomUUID().slice(0, 8)}`;
  const attemptDir = path.join(dir, 'specialist-attempts', attemptId);
  fs.mkdirSync(attemptDir, { recursive: true });
  const ctx = makeCtx(repo, pre.inv, pre, attemptDir, opts);
  const results = [];
  for (const tool of only) {
    const jobId = `${e.executionId}:${attemptId}:${tool}`;
    let result;
    try {
      if (tool === 'codeql') result = A.codeql(repo, ctx, { language: pre.inv.mainLanguage, ram: pre.cost.requiredRamMB });
      else if (tool === 'semgrep') result = A.semgrep(repo, ctx, { scope: e.signalRouting.targets, maxTargets: opts.maxTargets });
      else if (tool === 'bandit') result = A.bandit(repo, ctx, { scope: e.signalRouting.targets, maxTargets: opts.maxTargets });
      else if (tool === 'shellcheck') result = A.shellcheck(repo, ctx, { scope: e.signalRouting.targets, maxTargets: opts.maxTargets });
      else if (tool === 'trivy' || tool === 'osv') result = A[tool](repo, ctx);
      else throw new Error(`unsupported specialist adapter: ${tool}`);
    } catch (error) {
      result = { tool, status: STATUS.ERROR, verdict: 'TOOL_ERROR', notApplicable: false, findings: [], findingCount: 0,
        coverage: { filesSeen: null, filesEligible: null, filesParsed: null, analysisCompleted: false, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: [`adapter threw: ${error.message}`] },
        cost: { wallClockMs: 0, timedOut: false }, notes: ['adapter failure isolated; remaining specialists continue'], rawArtifact: null, error: error.message };
    }
    result.version = result.version || (e.identity.specialistVersions && e.identity.specialistVersions[tool]) || null;
    result.jobId = jobId;
    result.scopeMode = ['codeql', 'trivy', 'osv'].includes(tool) ? 'REPOSITORY' : e.signalRouting.mode;
    result.findings = (result.findings || []).map((finding, index) => ({
      ...finding,
      specialistFindingId: 'SF-' + crypto.createHash('sha256').update(JSON.stringify([jobId, finding.rule || finding.kind, finding.file || '', finding.line || null, index])).digest('hex').slice(0, 16),
      jobId,
      promotionIds: promotionIdsForFinding(finding, e.signalRouting, result.scopeMode, repo),
    }));
    ctx.charge(tool, result.cost && result.cost.wallClockMs);
    e.tools[tool] = result;
    results.push({ jobId, tool, status: result.status, version: result.version, scopeMode: result.scopeMode,
      targets: result.scopeMode === 'REPOSITORY' ? [repo] : e.signalRouting.targets,
      promotionIds: result.scopeMode === 'REPOSITORY' ? [] : e.signalRouting.promotions.map((p) => p.promotionId),
      findingCount: result.findingCount, durationMs: result.cost && result.cost.wallClockMs || 0,
      timedOut: !!(result.cost && result.cost.timedOut), rawArtifact: result.rawArtifact, error: result.error });
    const normalized = path.join(attemptDir, 'specialists', tool, 'normalized', 'findings.json');
    fs.mkdirSync(path.dirname(normalized), { recursive: true });
    fs.writeFileSync(normalized, JSON.stringify(result.findings, null, 2), { flag: 'wx' });
  }
  const allEnvelopes = Object.values(e.tools);
  const joined = correlate(repo, allEnvelopes, loadConfig().policies);
  for (const group of [joined.candidates, joined.observations]) for (const item of group) {
    item.commit = e.commit; item.tree = e.tree;
  }
  e.candidates = joined.candidates;
  e.observations = joined.observations;
  e.nonProductionSignals = joined.nonProductionSignals;
  e.auditVerdict = auditVerdict(allEnvelopes, openCandidates(e.candidates));
  const allCompleted = new Set([...completedTools, ...only]);
  const continuation = { status: routed.every((tool) => allCompleted.has(tool)) ? 'SUCCESS' : 'IN_PROGRESS', attemptId, selectedTools: only, jobs: results, completedAt: new Date().toISOString() };
  e.specialistAttempts = [...attempts, continuation];
  e.specialistContinuation = continuation;
  fs.writeFileSync(path.join(attemptDir, 'jobs.json'), JSON.stringify(results, null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(attemptDir, 'candidate-ledger.json'), JSON.stringify(e.candidates, null, 2), { flag: 'wx' });
  fs.writeFileSync(path.join(dir, 'specialist-jobs.json'), JSON.stringify(results, null, 2));
  fs.writeFileSync(path.join(dir, 'correlation', 'candidate-ledger.json'), JSON.stringify(e.candidates, null, 2));
  fs.writeFileSync(file, JSON.stringify(e, null, 2));
  fs.writeFileSync(path.join(dir, 'report', 'REPORT.json'), JSON.stringify(e, null, 2));
  renderReport(e);
  return { expediente: e, attemptDir };
}

module.exports = { runSpecialists };
