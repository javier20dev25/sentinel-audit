'use strict';
/**
 * Verdict matrix proof.
 *
 * A candidate blocks a clean claim unless its disposition answers "is there an
 * issue?" with a definitive no. This harness walks the whole disposition
 * vocabulary and asserts the exact verdict for each one, so the two paths that
 * compute a verdict (a fresh audit, and a re-verdict after adjudication) can
 * never drift apart again.
 *
 * Run: node tools/verdict-matrix.js
 */
const { openCandidates, RESOLVED_NO_ISSUE, PRIORITY, REVIEW, adjudicate, auditVerdict } = require('../correlate');
const { buildRoutePlan } = require('../workflow/audit');

const HEALTHY = [
  { tool: 'codeql', status: 'RAN', verdict: 'FULL_COVERAGE', coverage: { errors: [] }, notes: [], error: null },
  { tool: 'semgrep', status: 'RAN', verdict: 'FULL_COVERAGE', coverage: { errors: [] }, notes: [], error: null },
  { tool: 'trivy', status: 'RAN', verdict: 'FULL_COVERAGE', coverage: { errors: [] }, notes: [], error: null },
];
const SKIPPED_OSV = { tool: 'osv', status: 'SKIPPED', verdict: 'LIMITED_COVERAGE', coverage: { errors: ['no lockfile'] }, notes: ['no lockfile'], error: 'no lockfile' };

/** blocks = the candidate must keep the audit open. */
const MATRIX = [
  ['CONFIRMED_SECURITY_ISSUE', true],
  ['STRONG_SECURITY_CANDIDATE', true],
  ['PLAUSIBLE_SECURITY_ISSUE', true],
  ['UNRESOLVED', true],
  ['STATIC_ONLY_LIMITATION', true],
  ['BENIGN', false],
  ['TOOLING_INTENT', false],
  ['FALSE_POSITIVE', false],
  ['DUPLICATE', false],
  ['ALREADY_MITIGATED', false],
  ['OUT_OF_SCOPE', false],
];

let failures = 0;
function check(label, actual, expected) {
  const ok = actual === expected;
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label.padEnd(58)} got=${String(actual).padEnd(18)} want=${expected}`);
}

function candidate(disposition) {
  return { candidateId: 'T-1', file: 'a.js', line: 1, signals: [], disposition, reportable: undefined };
}

console.log('verdict matrix: which dispositions may claim clean\n');
console.log('adjudicated candidate -> open set size and verdict');
for (const [disp, blocks] of MATRIX) {
  const c = candidate(disp);
  adjudicate(c, { disposition: disp, state: 'MANUALLY_VERIFIED', rationale: 'matrix proof' });
  const open = openCandidates([c]);
  const v = auditVerdict(HEALTHY, open);
  check(`${disp} blocks clean`, open.length === 1 && v.canClaimClean === false, blocks);
  if (!blocks) {
    check(`  ${disp} verdict`, v.verdict, 'CLEAN_WITH_FULL_COVERAGE');
  } else {
    check(`  ${disp} verdict`, v.verdict, 'CANDIDATES_FOUND');
  }
}

console.log('\nunadjudicated candidate (default disposition) stays open');
const fresh = candidate('PLAUSIBLE_SECURITY_ISSUE');
fresh.reportable = undefined;
check('unadjudicated blocks clean', auditVerdict(HEALTHY, openCandidates([fresh])).canClaimClean, false);

console.log('\nthe two verdict paths agree');
const freshPath = auditVerdict(HEALTHY, openCandidates([candidate('PLAUSIBLE_SECURITY_ISSUE')]));
const adjPath = auditVerdict(HEALTHY, (() => { const c = candidate('PLAUSIBLE_SECURITY_ISSUE'); adjudicate(c, { disposition: 'PLAUSIBLE_SECURITY_ISSUE' }); return openCandidates([c]); })());
check('fresh vs adjudicated canClaimClean', adjPath.canClaimClean, freshPath.canClaimClean);
check('fresh vs adjudicated verdict', adjPath.verdict, freshPath.verdict);

console.log('\nreportable flag and open set never contradict each other');
for (const [disp, blocks] of MATRIX) {
  const c = candidate(disp);
  adjudicate(c, { disposition: disp, state: 'MANUALLY_VERIFIED' });
  const isOpen = openCandidates([c]).length === 1;
  const contradictory = isOpen && c.reportable === false && disp !== 'PLAUSIBLE_SECURITY_ISSUE' && disp !== 'UNRESOLVED' && disp !== 'STATIC_ONLY_LIMITATION';
  check(`${disp} reportable=${c.reportable} coherent with open=${isOpen}`, contradictory, false);
}

console.log('\nsafe-list only contains no-issue dispositions');
check('RESOLVED_NO_ISSUE size', RESOLVED_NO_ISSUE.size, 6);
for (const d of ['CONFIRMED_SECURITY_ISSUE', 'STRONG_SECURITY_CANDIDATE', 'PLAUSIBLE_SECURITY_ISSUE', 'UNRESOLVED', 'STATIC_ONLY_LIMITATION']) {
  check(`${d} not in safe-list`, RESOLVED_NO_ISSUE.has(d), false);
}

console.log('\ndegraded tool still blocks clean regardless of candidates');
check('degraded + all-safe candidates', auditVerdict([SKIPPED_OSV], openCandidates([(() => { const c = candidate('BENIGN'); adjudicate(c, { disposition: 'BENIGN' }); return c; })()])).canClaimClean, false);

console.log('\ninvestigation priority is verdict-neutral and never severity');
{
  // Same disposition, every priority: the verdict must not move.
  for (const disp of ['CONFIRMED_SECURITY_ISSUE', 'PLAUSIBLE_SECURITY_ISSUE', 'BENIGN', 'UNRESOLVED']) {
    const seen = new Set();
    for (const p of ['', 'P0', 'P1', 'P2', 'P3']) {
      const c = candidate(disp);
      adjudicate(c, { disposition: disp, priority: p || null });
      const v = auditVerdict(HEALTHY, openCandidates([c]));
      seen.add(`${v.verdict}|${v.canClaimClean}|${c.reportable}`);
    }
    check(`${disp}: identical verdict across P0-P3 and unset`, seen.size, 1);
  }
  // Priority must not leak into the reportable flag either.
  const p0 = candidate('BENIGN'); adjudicate(p0, { disposition: 'BENIGN', priority: 'P0' });
  const p3 = candidate('BENIGN'); adjudicate(p3, { disposition: 'BENIGN', priority: 'P3' });
  check('P0 vs P3 same reportable', p0.reportable, p3.reportable);
  // P0 on a no-issue disposition must not resurrect it as open.
  check('P0 + BENIGN stays closed', openCandidates([p0]).length, 0);
  check('P0 stored on candidate', p0.investigationPriority, 'P0');
  check('priority unset stays null', candidate('BENIGN').investigationPriority, undefined);
  const c2 = candidate('BENIGN'); adjudicate(c2, { disposition: 'BENIGN' });
  check('adjudicate without priority leaves it null', c2.investigationPriority, null);
  check('PRIORITY vocabulary', Object.keys(PRIORITY).sort().join(','), 'P0,P1,P2,P3');
}

console.log('\nreview state is workflow only, never an analytic input');
{
  // UNREVIEWED and REVIEWED must produce identical verdicts for the same
  // disposition, otherwise the field is covertly deciding something.
  for (const disp of ['CONFIRMED_SECURITY_ISSUE', 'PLAUSIBLE_SECURITY_ISSUE', 'BENIGN', 'OUT_OF_SCOPE', 'UNRESOLVED']) {
    const unreviewed = candidate(disp);
    unreviewed.reviewState = 'UNREVIEWED';
    const reviewed = candidate(disp);
    reviewed.reviewState = 'REVIEWED';
    const a = auditVerdict(HEALTHY, openCandidates([unreviewed]));
    const b = auditVerdict(HEALTHY, openCandidates([reviewed]));
    check(`${disp}: UNREVIEWED === REVIEWED (verdict)`, b.verdict, a.verdict);
    check(`${disp}: UNREVIEWED === REVIEWED (canClaimClean)`, b.canClaimClean, a.canClaimClean);
  }
  // A fresh candidate is UNREVIEWED and a plain-looking disposition.
  const fresh = candidate('PLAUSIBLE_SECURITY_ISSUE');
  delete fresh.reviewState;
  check('fresh candidate reads UNREVIEWED by default disposition', fresh.disposition, 'PLAUSIBLE_SECURITY_ISSUE');
  // Adjudicating marks REVIEWED.
  const adj = candidate('PLAUSIBLE_SECURITY_ISSUE');
  adjudicate(adj, { disposition: 'PLAUSIBLE_SECURITY_ISSUE' });
  check('adjudicated candidate is REVIEWED', adj.reviewState, 'REVIEWED');
  // The distinction is visible where it matters: untriaged work is countable.
  check('UNREVIEWED + PLAUSIBLE is still open', openCandidates([fresh]).length, 1);
  check('REVIEWED + BENIGN is closed', (() => { const c = candidate('BENIGN'); adjudicate(c, { disposition: 'BENIGN' }); return openCandidates([c]).length; })(), 0);
  // reviewState must not leak into reportable.
  const u = candidate('CONFIRMED_SECURITY_ISSUE'); u.reviewState = 'UNREVIEWED';
  const r = candidate('CONFIRMED_SECURITY_ISSUE'); r.reviewState = 'REVIEWED';
  check('reportable ignores reviewState', u.reportable, r.reportable);
  check('REVIEW vocabulary', Object.keys(REVIEW).sort().join(','), 'REVIEWED,UNREVIEWED');
}

console.log('\nSentinel-first: observation vs candidate vs confirmed');
{
  const { signalClassOf, correlate } = require('../correlate');
  const policies = require('../config/policies.json');
  const root = 'C:/repo';
  const senEnv = (findings) => ({
    tool: 'sentinel', status: 'SUCCESS', notApplicable: false, coverage: { filesSeen: 10, filesEligible: 10, filesParsed: 10, analysisCompleted: true, errors: [] },
    notes: [], error: null, findings,
  });
  const auth = (tool, extra) => ({ tool, status: 'SUCCESS', notApplicable: false, coverage: { filesSeen: 10, filesEligible: 10, filesParsed: 10, analysisCompleted: true, errors: [] }, notes: [], error: null, findings: [{ tool, rule: 'r1', file: root + '/src/a.js', line: 10, detail: 'evidence', ...extra }] });

  check('breadth kind defaults to OBSERVATION_ONLY', signalClassOf('sentinel', { kind: 'import', detail: 'x' }), 'OBSERVATION_ONLY');
  check('authority kind defaults to ACTIONABLE_SIGNAL', signalClassOf('codeql', { kind: 'dataflow', detail: 'x' }), 'ACTIONABLE_SIGNAL');
  check('empty detail forces OBSERVATION_ONLY even from an authority', signalClassOf('codeql', { kind: 'dataflow', detail: '' }), 'OBSERVATION_ONLY');
  check('missing detail forces OBSERVATION_ONLY', signalClassOf('semgrep', { rule: 'r', detail: undefined }), 'OBSERVATION_ONLY');
  check('declared ACTIONABLE_SIGNAL is respected', signalClassOf('sentinel', { kind: 'exec', detail: 'api=eval', signalClass: 'ACTIONABLE_SIGNAL' }), 'ACTIONABLE_SIGNAL');

  const breadthOnly = correlate(root, [senEnv([
    { tool: 'sentinel', kind: 'import', rule: 'import', file: root + '/src/a.js', line: 1, detail: 'source=lodash', signalClass: 'OBSERVATION_ONLY' },
    { tool: 'sentinel', kind: 'string', rule: 'string', file: root + '/src/b.js', line: 2, detail: 'value=https://x', signalClass: 'OBSERVATION_ONLY' },
  ])], policies);
  check('breadth-only Sentinel produces 0 candidates', breadthOnly.candidates.length, 0);
  check('breadth-only Sentinel produces 2 observations', breadthOnly.observations.length, 2);
  check('breadth observation is labeled OBSERVATION_ONLY', breadthOnly.observations[0].signalClass, 'OBSERVATION_ONLY');
  check('breadth observation counts 0 actionable', breadthOnly.observations[0].actionableSignals, 0);

  const actionable = correlate(root, [senEnv([
    { tool: 'sentinel', kind: 'exec', rule: 'exec', file: root + '/src/c.js', line: 5, detail: 'api=eval arg=req.query.x sink=eval', signalClass: 'ACTIONABLE_SIGNAL' },
  ])], policies);
  check('Sentinel alone never becomes a candidate', actionable.candidates.length, 0);
  check('actionable Sentinel signal is still only an observation', actionable.observations.length, 1);
  check('actionable observation counts 1 actionable', actionable.observations[0].actionableSignals, 1);

  const withAuthority = correlate(root, [
    senEnv([{ tool: 'sentinel', kind: 'import', rule: 'import', file: root + '/src/a.js', line: 10, detail: 'source=x', signalClass: 'OBSERVATION_ONLY' }]),
    auth('codeql'),
  ], policies);
  check('authority + breadth at same site is a candidate', withAuthority.candidates.length, 1);
  check('candidate records its actionable signal count', withAuthority.candidates[0].actionableSignals, 1);
  check('candidate records its breadth-only count', withAuthority.candidates[0].breadthOnlySignals, 1);
  check('breadth signal is visibly not actionable in the candidate', withAuthority.candidates[0].signals.find((s) => s.tool === 'sentinel').signalClass, 'OBSERVATION_ONLY');

  const silentAuthority = correlate(root, [auth('codeql', { detail: '' })], policies);
  check('authority with empty detail cannot corroborate', silentAuthority.candidates.length, 0);
  check('and becomes an observation instead', silentAuthority.observations.length, 1);
}

console.log('\nNO_ACTIONABLE_SENTINEL_FINDINGS is not a clean claim');
{
  const ran = (t, sc) => ({ tool: t, status: 'SUCCESS', verdict: 'NO_SIGNALS_FULL_COVERAGE', notApplicable: false, signalCounts: sc || null, coverage: { filesSeen: 10, filesEligible: 10, filesParsed: 10, analysisCompleted: true, errors: [] }, notes: [], error: null, findings: [] });
  const closed = (t) => ({ tool: t, status: 'SKIPPED', verdict: 'NOT_APPLICABLE', notApplicable: true, coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true, errors: [] }, notes: ['NO_ACTIONABLE_SENTINEL_FINDINGS'], error: null, findings: [] });
  const LENSES = ['codeql', 'semgrep', 'bandit', 'shellcheck'];

  const v = auditVerdict([ran('sentinel', { total: 120, actionable: 0, observationOnly: 120 }), ...LENSES.map(closed), ran('trivy'), ran('osv')], openCandidates([]));
  check('closed Etapa B yields the sentinel-first verdict', v.verdict, 'NO_ACTIONABLE_SENTINEL_FINDINGS');
  check('it never claims clean', v.canClaimClean, false);
  check('it is marked not-a-security-claim', v.securityClaim, 'NOT_A_SECURITY_CLAIM');
  check('analysis state is still FULL', v.analysisState, 'FULL');
  check('statement says it is not SECURE', /NOT equivalent to SECURE/.test(v.statement), true);
  check('statement says no secondary analysis was routed', /no secondary tools were routed|no deep dataflow analysis/.test(v.statement), true);

  const withActionable = auditVerdict([ran('sentinel', { total: 120, actionable: 3, observationOnly: 117 }), ...LENSES.map(closed), ran('trivy')], openCandidates([]));
  check('a nonzero actionable count never yields the sentinel-first verdict', withActionable.verdict, 'CLEAN_WITH_FULL_COVERAGE');
  check('and a real Etapa A hit keeps the clean claim available', withActionable.canClaimClean, true);

  const degraded = auditVerdict([ran('sentinel', { total: 5, actionable: 0, observationOnly: 5 }), ...LENSES.map(closed), { tool: 'trivy', status: 'ERROR', verdict: 'TOOL_ERROR', notApplicable: false, coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: false, errors: ['boom'] }, notes: [], error: 'boom', findings: [] }], openCandidates([]));
  check('a dead SCA tool outranks the sentinel-first verdict', degraded.verdict, 'PARTIAL_ANALYSIS');

  const c = candidate('PLAUSIBLE_SECURITY_ISSUE');
  check('an open candidate outranks the sentinel-first verdict', auditVerdict([ran('sentinel', { total: 5, actionable: 0, observationOnly: 5 }), ...LENSES.map(closed), ran('trivy')], openCandidates([c])).verdict, 'CANDIDATES_FOUND');

  const allRan = auditVerdict([ran('sentinel', { total: 5, actionable: 0, observationOnly: 5 }), ran('codeql'), ran('semgrep'), ran('trivy')], openCandidates([]));
  check('sentinel-first verdict cannot fire when Etapa B actually ran', allRan.verdict, 'CLEAN_WITH_FULL_COVERAGE');
}

console.log('\nSignal-first routing is explicit and deterministic');
{
  const none = buildRoutePlan([]);
  check('no signal routes no secondary tools', none.tools.length, 0);
  check('no signal records no-action state', none.decision, 'NO_ACTIONABLE_SENTINEL_FINDINGS');
  const crashed = buildRoutePlan([], 'ERROR');
  check('a crashed Etapa A is never a no-action claim', crashed.decision, 'SENTINEL_ENGINE_INCOMPLETE');
  check('a crashed Etapa A is flagged engineIncomplete', crashed.engineIncomplete, true);
  check('a crashed Etapa A says absence is not evidence of absence', /not evidence of absence/.test(crashed.reason), true);
  check('a crashed Etapa A routes no secondary tools', crashed.tools.length, 0);
  const crashedWithHits = buildRoutePlan([{ signalClass: 'ACTIONABLE_SIGNAL', category: 'process', file: 'src/run.js' }], 'ERROR');
  check('a crashed Etapa A never reports AMPLIFY', crashedWithHits.decision, 'SENTINEL_ENGINE_INCOMPLETE');
  const processJs = buildRoutePlan([{ signalClass: 'ACTIONABLE_SIGNAL', category: 'process', file: 'src/run.js' }]);
  check('process signal routes CodeQL and Semgrep', processJs.tools.join(','), 'codeql,semgrep');
  const processPy = buildRoutePlan([{ signalClass: 'ACTIONABLE_SIGNAL', category: 'process', file: 'src/run.py' }]);
  check('Python process signal additionally routes Bandit', processPy.tools.join(','), 'codeql,semgrep,bandit');
  const dependency = buildRoutePlan([{ signalClass: 'ACTIONABLE_SIGNAL', category: 'dependency', file: 'package-lock.json' }]);
  check('dependency signal routes only SCA specialists', dependency.tools.join(','), 'trivy,osv');
  const unmeasured = auditVerdict([
    { tool: 'sentinel', status: 'PARTIAL', verdict: 'LIMITED_COVERAGE', signalCounts: { total: 0, actionable: 0, observationOnly: 0 }, coverage: { engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', filesSeen: 3, filesEligible: null, filesParsed: null, analysisCompleted: false, errors: ['coverage unmeasured'] }, findings: [], notes: [], error: null },
    ...['codeql', 'semgrep', 'bandit', 'shellcheck', 'trivy', 'osv'].map((tool) => ({ tool, status: 'SKIPPED', verdict: 'NOT_APPLICABLE', notApplicable: true, coverage: { errors: [] }, findings: [], notes: [], error: null })),
  ], openCandidates([]));
  check('unmeasured zero-signal cannot claim clean', unmeasured.canClaimClean, false);
  check('unmeasured zero-signal keeps explicit no-action state', unmeasured.verdict, 'NO_ACTIONABLE_SENTINEL_FINDINGS');
}

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
