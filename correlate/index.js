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

/** Roles decide what a corroboration is worth. Sentinel Cloud is never sufficient alone. */
const AUTHORITY = {
  codeql: 'dataflow_authority',
  bandit: 'sink_semantics',
  semgrep: 'pattern',
  sentinel: 'behaviour_breadth',
  trivy: 'dependency_config',
  osv: 'dependency_intel',
  shellcheck: 'lint_only',
};
/** A finding only becomes a hypothesis if a real authority saw it. */
const SUFFICIENT_TO_CORROBORATE = new Set(['codeql', 'bandit', 'semgrep']);

/**
 * First-class signal class. A breadth lens produces volume, not severity, and
 * volume must never be promotable to a candidate on its own. Tools that do not
 * declare a class are treated by their standing: a pattern/dataflow/sink
 * authority is actionable by construction, a breadth or hypothesis lens is not.
 */
const DEFAULT_SIGNAL_CLASS = {
  sentinel: 'OBSERVATION_ONLY',
  shellcheck: 'OBSERVATION_ONLY',
  codeql: 'ACTIONABLE_SIGNAL',
  semgrep: 'ACTIONABLE_SIGNAL',
  bandit: 'ACTIONABLE_SIGNAL',
  trivy: 'ACTIONABLE_SIGNAL',
  osv: 'ACTIONABLE_SIGNAL',
};

const isObservationClass = (c) => String(c || '').toUpperCase() !== 'ACTIONABLE_SIGNAL';

/**
 * An empty detail is never evidence. This guard is central and unconditional so
 * that no tool, present or future, can promote a signal that carries no
 * explanation into an actionable one.
 */
const signalClassOf = (tool, f) => {
  if (f.detail === '' || f.detail === undefined || f.detail === null) return 'OBSERVATION_ONLY';
  if (f.signalClass) return f.signalClass;
  return DEFAULT_SIGNAL_CLASS[tool] || 'ACTIONABLE_SIGNAL';
};


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
  if (!relPath) return 'UNKNOWN';
  const lower = '/' + relPath.toLowerCase();
  const parts = lower.split('/');
  const base = parts[parts.length - 1];
  if (policies.coverage.testPathHints.some((h) => lower.includes(h) || base.includes(h.replace(/\//g, '')))) return 'TEST';
  if (parts.some((p) => ['node_modules', 'vendor', 'third_party'].includes(p))) return 'NON_PRODUCTION';
  if (parts.some((p) => ['dist', 'build', 'compiled'].includes(p))) return 'GENERATED';
  if (/\/(?:example|examples)\//.test(lower)) return 'EXAMPLE';
  if (policies.coverage.nonProductionPathHints.some((h) => lower.includes(h))) return 'NON_PRODUCTION';
  if (/^(test|tests|__tests__|spec|specs)\//.test(lower)) return 'TEST';
  if (parts.some((p) => ['docs', 'documentation'].includes(p)) || /\.(md|rst|adoc|txt)$/i.test(base)) return 'DOC';
  if (/\.(min\.js|bundle\.js|generated\.[tj]s)$/.test(base) || base.includes('.pb.')) return 'GENERATED';
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
      endLine: f.endLine || null,
      signalId: f.signalId || null,
      specialistFindingId: f.specialistFindingId || null,
      jobId: f.jobId || null,
      promotionIds: f.promotionIds || [],
      severity: f.level || f.severity || null,
      signalClass: signalClassOf(e.tool, f),
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
    const r = rel(root, f.file);
    const scope = scopeOf(r, policies);
    if (scope === 'PRODUCTION') continue;
    // A signal excluded by scope still has to carry the evidence that justifies
    // the exclusion, otherwise "we looked and it was not shipped" is unfalsifiable.
    out.push({
      tool: e.tool, rule: f.rule || f.kind, file: r, line: f.line, scope,
      disposition: 'OUT_OF_SCOPE', status: 'OUT_OF_SCOPE',
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
  endLine: s.endLine || null,
  severity: s.severity || null,
  signalId: s.signalId || null,
  specialistFindingId: s.specialistFindingId || null,
  jobId: s.jobId || null,
  promotionIds: s.promotionIds || [],
  file: s.file || null,
  signalClass: s.signalClass || 'ACTIONABLE_SIGNAL',
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
  const cloudByFile = new Map();
  for (const e of envelopes.filter((x) => x.tool === 'sentinel')) for (const f of e.findings || []) {
    if (!f.file || !f.signalId) continue;
    const key = path.resolve(f.file).toLowerCase();
    if (!cloudByFile.has(key)) cloudByFile.set(key, []);
    cloudByFile.get(key).push(f);
  }
  const candidates = [];
  const observations = [];
  let n = 0;
  for (const [key, signals] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const tools = [...new Set(signals.map((s) => s.tool))];
    // A tool only corroborates if the signal it contributed survived the actionability
    // gate. An authority that emitted an empty detail has stated nothing, so counting
    // it here would launder a silent tool into a confidence word.
    const authorities = tools.filter((t) => SUFFICIENT_TO_CORROBORATE.has(t)
      && signals.some((s) => s.tool === t && !isObservationClass(s.signalClass)));
    const actionableSignals = signals.filter((s) => !isObservationClass(s.signalClass));
    const file = signals[0].file || key.split('|')[1];
    const fileCloudSignals = cloudByFile.get(path.resolve(file).toLowerCase()) || [];
    const line = signals.find((s) => s.line) ? signals.find((s) => s.line).line : null;
    // A signal only from Sentinel Cloud is an OBSERVATION, not a candidate.
    // Calling breadth output "candidates"
    // is how a report ends up implying 64 unverified security issues.
    if (!authorities.length) {
      observations.push({
        observationId: 'OBS-' + String(observations.length + 1).padStart(4, '0'),
        file, line, tools,
        signalClass: 'OBSERVATION_ONLY',
        signalCount: signals.length,
        actionableSignals: actionableSignals.length,
        signals: signals.map(signalView),
        state: STATE.TRIAGED,
        status: actionableSignals.length ? 'BREADTH_SIGNAL_ONLY_NOT_A_CANDIDATE' : 'BREADTH_SIGNAL_NO_EVIDENCE',
        note: 'no dataflow or pattern authority corroborated this; it is a lead, not a finding',
      });
      continue;
    }
    const confidence = authorities.length >= 2 ? 'high' : 'medium';
    const specialist = signals.find((s) => s.tool !== 'sentinel' && SUFFICIENT_TO_CORROBORATE.has(s.tool)) || signals[0];
    const cloudSignalIds = [...new Set([
      ...signals.filter((s) => s.tool === 'sentinel').map((s) => s.signalId),
      ...fileCloudSignals.map((s) => s.signalId),
    ].filter(Boolean))];
    const promotionIds = [...new Set([
      ...signals.flatMap((s) => s.promotionIds || []),
      ...fileCloudSignals.flatMap((s) => s.promotionIds || []),
    ])];
    candidates.push({
      candidateId: 'SAR-' + String(++n).padStart(4, '0'),
      repo: root, repository: root,
      file, line, startLine: line,
      endLine: signals.find((s) => Number.isInteger(s.endLine))?.endLine || null,
      severity: signals.find((s) => s.tool !== 'sentinel' && s.severity)?.severity || null,
      tool: specialist.tool || null,
      rule: specialist.rule || null,
      message: specialist.detail || null,
      scope: scopeOf(rel(root, file), policies),
      evidence: signals.map(signalView),
      correlationId: 'COR-' + crypto.createHash('sha256').update(`${file}|${key}`).digest('hex').slice(0, 16),
      signalIds: [...new Set(signals.map((s) => s.signalId).filter(Boolean))],
      promotionIds,
      jobIds: [...new Set(signals.map((s) => s.jobId).filter(Boolean))],
      specialistFindingIds: [...new Set(signals.map((s) => s.specialistFindingId).filter(Boolean))],
      cloudSignalId: cloudSignalIds[0] || null,
      promotionId: promotionIds[0] || null,
      jobId: specialist.jobId || null,
      specialistFindingId: specialist.specialistFindingId || null,
      cloudSignalAssociation: cloudSignalIds,
      cloudAssociationScope: fileCloudSignals.length ? 'FILE_EXACT_CO_OCCURRENCE_NOT_CAUSAL' : 'NO_CLOUD_SIGNAL_ON_FILE',
      routingAssociation: promotionIds,
      signals: signals.map(signalView),
      tools,
      signalCount: signals.length,
      actionableSignals: actionableSignals.length,
      breadthOnlySignals: signals.length - actionableSignals.length,
      corroboratingAuthorities: authorities,
      confidence,
      state: STATE.CORROBORATED,
      reviewState: REVIEW.UNREVIEWED,
      disposition: 'PLAUSIBLE_SECURITY_ISSUE',
      status: 'MANUAL_VERIFICATION_REQUIRED',
      candidateStatus: 'PLAUSIBLE_SECURITY_ISSUE',
      verificationStatus: 'MANUAL_VERIFICATION_REQUIRED',
      note: 'confidence reflects how many independent authorities saw this, nothing more',
    });
  }
  return { candidates, observations, nonProductionSignals: nonProduction(root, envelopes, policies) };
}

/**
 * Investigation priority, set by the analyst. This is NOT vulnerability
 * severity and must never be read as one: it answers "how soon should a human
 * look at this", not "how bad is this". A confirmed misconfiguration can be
 * P3, and an unproven hypothesis on a hot path can be P0.
 *
 * It is deliberately absent from every verdict computation below. A candidate
 * keeps a run open because of its disposition, never because of its priority,
 * so priority can never be used to quietly close or promote a finding.
 */
const PRIORITY = { P0: 'P0', P1: 'P1', P2: 'P2', P3: 'P3' };

/**
 * Review state, kept separate from disposition on purpose.
 *
 * A candidate's default disposition is PLAUSIBLE_SECURITY_ISSUE, which is a real
 * analytic conclusion, so leaving untouched candidates there made "nobody has
 * read this yet" indistinguishable from "an analyst read this and kept the
 * hypothesis". That conflation is how a backlog drains on paper while nothing
 * was actually reviewed.
 *
 *   PLAUSIBLE + UNREVIEWED  the tool produced it, no human has adjudicated it
 *   PLAUSIBLE + REVIEWED    an analyst looked and decided the hypothesis stands
 *
 * This is workflow bookkeeping only. It is not part of any verdict, it does not
 * change `reportable`, and it never changes a disposition.
 */
const REVIEW = { UNREVIEWED: 'UNREVIEWED', REVIEWED: 'REVIEWED' };

/** Apply an analyst decision. The runner never makes this call itself. */
function adjudicate(candidate, decision) {
  const d = decision || {};
  candidate.state = d.state || STATE.MANUALLY_VERIFIED;
  candidate.reviewState = REVIEW.REVIEWED;
  candidate.disposition = d.disposition || candidate.disposition;
  candidate.severity = d.severity || null;
  candidate.classification = d.classification || null;
  candidate.groundTruth = d.groundTruth || null;
  candidate.impact = d.impact || null;
  candidate.investigationPriority = d.priority || null;
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
  const terminalUnavailable = new Set(['ERROR', 'UNSUPPORTED', 'SKIPPED', 'UNAVAILABLE', 'INVALID', 'TIMEOUT', 'CANCELLED']);
  const degraded = applicable.filter((e) => e.status === 'PARTIAL' || terminalUnavailable.has(e.status));
  const hardFailed = applicable.filter((e) => terminalUnavailable.has(e.status));
  const limited = applicable.filter((e) => e.status === 'PARTIAL');
  const notClean = applicable.filter((e) => e.verdict.endsWith('LIMITED_COVERAGE') || e.status === 'PARTIAL' || terminalUnavailable.has(e.status));

  // Two orthogonal facts, kept as two fields on purpose. Collapsing them is how a
  // report ends up calling a run with dead tools "clean", or calling a run with
  // 12 real candidates "degraded" and burying the candidates.
  const analysisState = hardFailed.length ? 'PARTIAL_ANALYSIS' : limited.length ? 'LIMITED_COVERAGE' : 'FULL';

  // NO_ACTIONABLE_SENTINEL_FINDINGS is a real terminal state and is NOT a clean
  // claim. It means discovery ran, produced breadth, and the breadth contained
  // nothing that earned an expensive lens. That is a statement about Sentinel's
  // output, not about the target's security, so it can never set canClaimClean.
  const senEnv = applicable.find((e) => e.tool === 'sentinel');
  const etapaBClosed = !!senEnv && !(senEnv.signalCounts && senEnv.signalCounts.actionable > 0);

  // Audit never uses an absence-only terminal state as a security assurance.
  // A completed set of configured tools may have no candidates, but it has not
  // proven a repository clean across all vulnerability classes.
  const canClaimClean = false;
  const verdict = candidates.length > 0 ? 'CANDIDATES_FOUND'
    : etapaBClosed ? 'NO_ACTIONABLE_SENTINEL_FINDINGS'
      : hardFailed.length ? 'PARTIAL_ANALYSIS'
        : limited.length ? 'LIMITED_ANALYSIS' : 'COMPLETE_NO_CANDIDATES';

  return {
    verdict,
    analysisState,
    canClaimClean,
    securityClaim: etapaBClosed ? 'NOT_A_SECURITY_CLAIM' : null,
    requiredTools: required.length,
    notApplicableTools: notApplicable.map((e) => e.tool),
    degradedTools: degraded.map((e) => ({ tool: e.tool, status: e.status, verdict: e.verdict, reason: (e.coverage.errors || [])[0] || e.error || (e.notes || [])[0] || null })),
    skippedTools: skipped.map((e) => ({ tool: e.tool, reason: e.error || (e.notes || [])[0] || 'no reason recorded' })),
    notCleanTools: notClean.map((e) => e.tool),
    candidateCount: candidates.length,
    statement: verdict === 'CANDIDATES_FOUND'
      ? `${candidates.length} candidate(s) require human adjudication. ${degraded.length ? degraded.length + ' tool(s) also degraded, so absence of further findings is not evidence of absence.' : 'Tool coverage was complete.'}`
      : etapaBClosed
        ? `Sentinel Cloud produced 0 ACTIONABLE_SIGNAL, so no secondary tools were routed. This is NOT a security claim and NOT equivalent to SECURE.${senEnv.coverage && senEnv.coverage.engineCoverage === 'ENGINE_COVERAGE_UNMEASURED' ? ' Engine parsed-file coverage is unmeasured.' : ' No deep dataflow analysis was performed on this target.'}`
        : hardFailed.length
          ? `${hardFailed.length} of ${applicable.length} applicable tools did not run to completion (${hardFailed.map((e) => e.tool + '=' + e.status).join(', ')}). Absence of findings is NOT evidence of absence.`
          : limited.length
            ? `All ${applicable.length} applicable tools completed, but ${limited.length} had limited coverage (${limited.map((e) => e.tool).join(', ')}). Absence of findings is NOT evidence of absence.`
            : `All ${required.length} applicable tools completed. No candidate was generated by the configured policy; this is not a security-clean claim.` +
              (notApplicable.length ? ` ${notApplicable.length} were not applicable (${notApplicable.map((e) => e.tool).join(', ')}).` : ''),
  };
}
const STATUS_SKIPPED = 'SKIPPED';
const SOURCE_LENSES = ['codeql', 'semgrep', 'bandit', 'shellcheck'];

module.exports = { STATE, AUTHORITY, PRIORITY, REVIEW, RESOLVED_NO_ISSUE, openCandidates, correlate, adjudicate, auditVerdict, scopeOf, rel, dedup, nonProduction, signalClassOf, isObservationClass, DEFAULT_SIGNAL_CLASS };
