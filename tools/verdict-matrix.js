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
const { openCandidates, RESOLVED_NO_ISSUE, PRIORITY, adjudicate, auditVerdict } = require('../correlate');

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

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
