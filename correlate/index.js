'use strict';
/**
 * Correlation, deduplication, disposition and the finding state machine.
 *
 * All deterministic. No model, no probability, no guessing. A correlation
 * expresses "these independent lenses pointed at the same place", and nothing
 * more. Exploitability is always a human decision recorded as MANUAL_VERIFICATION_REQUIRED.
 */
const crypto = require('crypto');
const path = require('path');

const STATE = {
  DETECTED: 'DETECTED', TRIAGED: 'TRIAGED', CORROBORATED: 'CORROBORATED',
  DISPUTED: 'DISPUTED', MANUALLY_VERIFIED: 'MANUALLY_VERIFIED',
  REPORTABLE: 'REPORTABLE', NON_REPORTABLE: 'NON_REPORTABLE',
};

/** Roles decide what a corroboration is worth. Sentinel/Purple are never sufficient alone. */
const AUTHORITY = {
  codeql: 'dataflow_authority',
  bandit: 'sink_semantics',
  semgrep: 'pattern',
  sentinel: 'behaviour_breadth',
  purple: 'attack_hypothesis',
  trivy: 'dependency_config',
  osv: 'dependency_intel',
  shellcheck: 'lint_only',
};
/** A finding only becomes a hypothesis if a real authority saw it. */
const SUFFICIENT_TO_CORROBORATE = new Set(['codeql', 'bandit', 'semgrep']);

/**
 * Dispositions that answer the question "is there a security issue here?" with a
 * definitive no. Only these may stop a candidate from blocking a clean claim.
 *
 * Everything else, including CONFIRMED, STRONG, PLAUSIBLE, UNRESOLVED and
 * STATIC_ONLY_LIMITATION, keeps the audit open on purpose: "not reportable yet"
 * is not the same claim as "no issue", and collapsing the two is how a target
 * ends up badged clean while a live hypothesis is still sitting in the file.
 */
const RESOLVED_NO_ISSUE = new Set([
  'BENIGN', 'FALSE_POSITIVE', 'OUT_OF_SCOPE', 'TOOLING_INTENT',
  'ALREADY_MITIGATED', 'DUPLICATE',
]);

/** Candidates that still block a clean claim. Single definition, used by every caller. */
function openCandidates(candidates) {
  return (candidates || []).filter((x) => !RESOLVED_NO_ISSUE.has(String(x.disposition || '').trim().toUpperCase()));
}

const rel = (root, p) => {
  const s = path.resolve(String(p || '')).replace(/\\/g, '/');
  const r = path.resolve(root).replace(/\\/g, '/');
  return s.startsWith(r) ? s.slice(r.length).replace(/^\//, '') : s;
};

/** Scope buckets. Findings in non-shipped code are reclassified, not deleted. */
function scopeOf(relPath, policies) {
  const lower = '/' + relPath.toLowerCase();
  const parts = lower.split('/');
  const base = parts[parts.length - 1];
  if (policies.coverage.testPathHints.some((h) => lower.includes(h) || base.includes(h.replace(/\//g, '')))) return 'TEST';
  if (parts.some((p) => ['node_modules', 'vendor', 'third_party', 'dist', 'build', 'compiled'].includes(p))) return 'VENDORED';
  if (policies.coverage.nonProductionPathHints.some((h) => lower.includes(h))) return 'NON_PRODUCTION';
  if (/^(test|tests|__tests__|spec|specs)\//.test(lower)) return 'TEST';
  return 'PRODUCTION';
}

/** Cluster signals that plausibly describe the same defect. */
function dedup(root, envelopes, policies) {
  const buckets = new Map();
  for (const e of envelopes) for (const f of e.findings || []) {
    if (f.secret) continue;                       // never cluster or store secret material
    const r = rel(root, f.file);
    const scope = scopeOf(r, policies);
    if (scope !== 'PRODUCTION') continue;         // recorded separately, below
    const key = (f.line ? Math.round(f.line / (policies.correlation.lineProximity + 1)) : 0) + '|' + r;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push({
      tool: e.tool, rule: f.rule || f.kind, line: f.line, detail: f.detail,
      verdictFromTool: f.verdictFromTool, sha256: f.sha256 || null,
      snippet: f.snippet || null,
      source: f.source || null, sink: f.sink || null,
      sourceFile: f.sourceFile ? rel(root, f.sourceFile) : null, sourceLine: f.sourceLine || null,
      controls: f.controls || [], blockedBy: f.blockedBy || [],
      path: f.path || null,
    });
  }
  return buckets;
}

const nonProduction = (root, envelopes, policies) => {
  const out = [];
  for (const e of envelopes) for (const f of e.findings || []) {
    if (f.secret) continue;
    const r = rel(root, f.file);
    const scope = scopeOf(r, policies);
    if (scope === 'PRODUCTION') continue;
    // A signal excluded by scope still has to carry the evidence that justifies
    // the exclusion, otherwise "we looked and it was not shipped" is unfalsifiable.
    out.push({
      tool: e.tool, rule: f.rule || f.kind, file: r, line: f.line, scope,
      detail: f.detail, snippet: f.snippet || null, path: f.path || null,
      source: f.source || null, sink: f.sink || null,
      sourceFile: f.sourceFile ? rel(root, f.sourceFile) : null, sourceLine: f.sourceLine || null,
      controls: f.controls || [],
    });
  }
  return out;
};

/**
 * Correlate envelopes into candidates. This is the only place a "confidence"
 * word is produced, and it is derived from which lens saw what, not a model.
 */
const signalView = (s) => ({
  tool: s.tool, authority: AUTHORITY[s.tool], rule: s.rule, line: s.line,
  file: s.file || null,
  verdictFromTool: s.verdictFromTool || null,
  detail: s.detail,
  // Evidence that must survive so a reviewer never has to re-clone the target.
  snippet: s.snippet || null,
  source: s.source || null, sink: s.sink || null,
  sourceFile: s.sourceFile || null, sourceLine: s.sourceLine || null,
  path: s.path || null,
  controls: s.controls || [], blockedBy: s.blockedBy || [],
  sha256: s.sha256 || null,
});

function correlate(root, envelopes, policies) {
  const groups = dedup(root, envelopes, policies);
  const candidates = [];
  const observations = [];
  let n = 0;
  for (const [key, signals] of groups) {
    const tools = [...new Set(signals.map((s) => s.tool))];
    const authorities = tools.filter((t) => SUFFICIENT_TO_CORROBORATE.has(t));
    const file = signals[0].file || key.split('|')[1];
    const line = signals.find((s) => s.line) ? signals.find((s) => s.line).line : null;
    const purpleSaysEntailed = signals.some((s) => s.verdictFromTool === 'ENTAILED');
    // A signal only from a breadth or hypothesis lens is an OBSERVATION, not a
    // candidate. Sentinel alone is 54 files of noise; calling those "candidates"
    // is how a report ends up implying 64 unverified security issues.
    if (!authorities.length) {
      observations.push({
        observationId: 'OBS-' + String(observations.length + 1).padStart(4, '0'),
        file, line, tools,
        signals: signals.map(signalView),
        purpleEntailed: purpleSaysEntailed,
        state: STATE.TRIAGED,
        status: 'BREADTH_SIGNAL_ONLY_NOT_A_CANDIDATE',
        note: 'no dataflow or pattern authority corroborated this; it is a lead, not a finding',
      });
      continue;
    }
    const confidence = authorities.length >= 2 ? 'high' : 'medium';
    candidates.push({
      candidateId: 'SAR-' + String(++n).padStart(4, '0'),
      repo: root,
      file, line,
      signals: signals.map(signalView),
      tools,
      corroboratingAuthorities: authorities,
      confidence,
      state: STATE.CORROBORATED,
      disposition: 'PLAUSIBLE_SECURITY_ISSUE',
      status: 'MANUAL_VERIFICATION_REQUIRED',
      note: 'confidence reflects how many independent authorities saw this, nothing more',
    });
  }
  return { candidates, observations, nonProductionSignals: nonProduction(root, envelopes, policies) };
}

/** Apply an analyst decision. The runner never makes this call itself. */
function adjudicate(candidate, decision) {
  const d = decision || {};
  candidate.state = d.state || STATE.MANUALLY_VERIFIED;
  candidate.disposition = d.disposition || candidate.disposition;
  candidate.severity = d.severity || null;
  candidate.classification = d.classification || null;
  candidate.groundTruth = d.groundTruth || null;
  candidate.impact = d.impact || null;
  candidate.rationale = d.rationale || null;
  candidate.reportable = candidate.disposition === 'CONFIRMED_SECURITY_ISSUE' || candidate.disposition === 'STRONG_SECURITY_CANDIDATE';
  candidate.fingerprint = crypto.createHash('sha256').update(candidate.file + ':' + (candidate.line || 0)).digest('hex').slice(0, 16);
  return candidate;
}

/**
 * The audit-level verdict. A single degraded tool can never produce CLEAN.
 * This is Gate A made observable at the top of the report.
 */
function auditVerdict(envs, candidates) {
  const applicable = envs.filter((e) => !e.notApplicable);
  const notApplicable = envs.filter((e) => e.notApplicable);
  const required = applicable.filter((e) => e.status !== STATUS_SKIPPED);
  const skipped = applicable.filter((e) => e.status === STATUS_SKIPPED);
  // A tool that never ran is not coverage. It was excluded from `degraded` here
  // once and the run reported CLEAN_WITH_FULL_COVERAGE with a skipped OSV: the
  // tool's own note said "COVERAGE GAP and not a clean result" and the
  // aggregate never read it. Skipped is therefore a hard coverage failure.
  const degraded = applicable.filter((e) => e.status === 'PARTIAL' || e.status === 'ERROR' || e.status === 'UNSUPPORTED' || e.status === STATUS_SKIPPED);
  const hardFailed = applicable.filter((e) => e.status === 'ERROR' || e.status === 'UNSUPPORTED' || e.status === STATUS_SKIPPED);
  const limited = applicable.filter((e) => e.status === 'PARTIAL');
  const notClean = applicable.filter((e) => e.verdict.endsWith('LIMITED_COVERAGE') || e.status === 'PARTIAL' || e.status === STATUS_SKIPPED);

  // Two orthogonal facts, kept as two fields on purpose. Collapsing them is how a
  // report ends up calling a run with dead tools "clean", or calling a run with
  // 12 real candidates "degraded" and burying the candidates.
  const analysisState = hardFailed.length ? 'PARTIAL_ANALYSIS' : limited.length ? 'LIMITED_COVERAGE' : 'FULL';
  const canClaimClean = degraded.length === 0 && candidates.length === 0;
  const verdict = candidates.length > 0 ? 'CANDIDATES_FOUND' : hardFailed.length ? 'PARTIAL_ANALYSIS' : limited.length ? 'CLEAN_WITH_LIMITATIONS' : 'CLEAN_WITH_FULL_COVERAGE';

  return {
    verdict,
    analysisState,
    canClaimClean,
    requiredTools: required.length,
    notApplicableTools: notApplicable.map((e) => e.tool),
    degradedTools: degraded.map((e) => ({ tool: e.tool, status: e.status, verdict: e.verdict, reason: (e.coverage.errors || [])[0] || e.error || (e.notes || [])[0] || null })),
    skippedTools: skipped.map((e) => ({ tool: e.tool, reason: e.error || (e.notes || [])[0] || 'no reason recorded' })),
    notCleanTools: notClean.map((e) => e.tool),
    candidateCount: candidates.length,
    statement: verdict === 'CANDIDATES_FOUND'
      ? `${candidates.length} candidate(s) require human adjudication. ${degraded.length ? degraded.length + ' tool(s) also degraded, so absence of further findings is not evidence of absence.' : 'Tool coverage was complete.'}`
      : hardFailed.length
        ? `${hardFailed.length} of ${applicable.length} applicable tools did not run to completion (${hardFailed.map((e) => e.tool + '=' + e.status).join(', ')}). Absence of findings is NOT evidence of absence.`
        : limited.length
          ? `All ${applicable.length} applicable tools completed, but ${limited.length} had limited coverage (${limited.map((e) => e.tool).join(', ')}). Absence of findings is NOT evidence of absence.`
          : `All ${required.length} applicable tools completed with full coverage.` +
            (notApplicable.length ? ` ${notApplicable.length} not applicable to this target (${notApplicable.map((e) => e.tool).join(', ')}), excluded from the claim.` : ''),
  };
}
const STATUS_SKIPPED = 'SKIPPED';

module.exports = { STATE, AUTHORITY, RESOLVED_NO_ISSUE, openCandidates, correlate, adjudicate, auditVerdict, scopeOf, rel, dedup, nonProduction };
