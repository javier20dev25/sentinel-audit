/**
 * Sentinel Y v0.2 Hardened Evaluation Runner
 * Executes Phase Y2.2 evaluation across:
 * 1. Calibration Regression Fixtures (4 pairs: deep-extend, mixin-deep, tough-cookie, cross-spawn)
 * 2. Diagnostic Regression Fixtures (json5, minimist, json-pointer)
 * 3. Benign Control Negative Fixtures (Expanded to 10 controls)
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { v02 } = require('../../sentinel-y');
const { analyzeFile } = v02;

const manifestPath = path.resolve(__dirname, '../phase5/PHASE5_MANIFEST.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const cloneBase = path.resolve(__dirname, '../phase5/clones');

// 1. Calibration Regressions (Must maintain 100% paired discrimination)
const calibrationFixtures = [
  { id: 'P5-013', role: 'CALIBRATION_REGRESSION', pkg: 'deep-extend', cve: 'CVE-2018-3750', rule: 'Y-PROTO-001', file: 'lib/deep-extend.js' },
  { id: 'P5-015', role: 'CALIBRATION_REGRESSION', pkg: 'mixin-deep', cve: 'CVE-2019-10746', rule: 'Y-PROTO-001', file: 'index.js' },
  { id: 'P5-033', role: 'CALIBRATION_REGRESSION', pkg: 'tough-cookie', cve: 'CVE-2017-15010', rule: 'Y-REDOS-001', file: 'lib/cookie.js' },
  { id: 'P5-041', role: 'CALIBRATION_REGRESSION', pkg: 'cross-spawn', cve: 'CVE-2024-21538', rule: 'Y-REDOS-001', file: 'lib/util/escape.js' }
];

// 2. Diagnostic Regressions (json5 structural fix + persistent alert fixtures)
const diagnosticFixtures = [
  { id: 'P5-029', role: 'DIAGNOSTIC_REGRESSION', pkg: 'json5', cve: 'CVE-2022-46175', rule: 'Y-PROTO-001', file: 'src/parse.js' },
  { id: 'P5-011', role: 'DIAGNOSTIC_REGRESSION', pkg: 'minimist', cve: 'CVE-2021-44906', rule: 'Y-PROTO-001', file: 'index.js' },
  { id: 'P5-016', role: 'DIAGNOSTIC_REGRESSION', pkg: 'json-pointer', cve: 'CVE-2022-4742', rule: 'Y-PROTO-001', file: 'index.js' }
];

// 3. Expanded Benign Negative Controls (10 controls, including jsonwebtoken, ejs, socket.io)
const benignControls = [
  { id: 'CTRL-01', pId: 'P5-019', pkg: 'axios', file: 'lib/adapters/http.js', reason: 'HTTP client core transport without property mergers' },
  { id: 'CTRL-02', pId: 'P5-023', pkg: 'node-fetch', file: 'src/index.js', reason: 'Fetch implementation without object prototype mutations' },
  { id: 'CTRL-03', pId: 'P5-010', pkg: 'jsonwebtoken', file: 'index.js', reason: 'Token verification with shallow header/options copy' },
  { id: 'CTRL-04', pId: 'P5-012', pkg: 'nodemailer', file: 'lib/nodemailer.js', reason: 'Mailer facade without dynamic property writing' },
  { id: 'CTRL-05', pId: 'P5-025', pkg: 'ejs', file: 'lib/ejs.js', reason: 'Template compiler options merging into internal dict' },
  { id: 'CTRL-06', pId: 'P5-042', pkg: 'body-parser', file: 'lib/types/urlencoded.js', reason: 'URL parser without recursive property iteration' },
  { id: 'CTRL-07', pId: 'P5-045', pkg: 'socket.io', file: 'lib/manager.js', reason: 'Connection manager with internal this.settings dictionary' },
  { id: 'CTRL-08', pId: 'P5-001', pkg: 'handlebars', file: 'lib/handlebars/runtime.js', reason: 'Template runtime environment without prototype mutation' },
  { id: 'CTRL-09', pId: 'P5-037', pkg: 'jsonwebtoken', file: 'index.js', reason: 'Key verification without ReDoS or prototype pollution' },
  { id: 'CTRL-10', pId: 'P5-006', pkg: 'mongoose', file: 'lib/document.js', reason: 'Patched document schema validator' }
];

function fetchFile(repoDir, sha, file) {
  try {
    return execSync(`git show ${sha}:${file}`, { cwd: repoDir, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
  } catch (e) {
    return null;
  }
}

const resultsJsonl = path.resolve(__dirname, 'PHASE_Y2_2_RESULTS.jsonl');
fs.writeFileSync(resultsJsonl, '');

const allPairs = [...calibrationFixtures, ...diagnosticFixtures];
const evaluatedPairs = [];

console.log('=== EVALUATING SENTINEL Y v0.2 PAIRS ===\n');

allPairs.forEach(target => {
  const entry = manifest.entries.find(e => e.id === target.id);
  const repoDir = path.join(cloneBase, path.basename(entry.clonePath));

  const vSrc = fetchFile(repoDir, entry.vulnerableSha, target.file);
  const pSrc = fetchFile(repoDir, entry.fixSha, target.file);

  const vFindingsAll = vSrc ? analyzeFile(target.file, vSrc).filter(f => f.ruleId === target.rule) : [];
  const pFindingsAll = pSrc ? analyzeFile(target.file, pSrc).filter(f => f.ruleId === target.rule) : [];

  // Binary alert rule: only CONFIRMED findings trigger vulnerability alerts
  const vFindingsConfirmed = vFindingsAll.filter(f => f.verdict === 'CONFIRMED');
  const pFindingsConfirmed = pFindingsAll.filter(f => f.verdict === 'CONFIRMED');

  const vAlert = vFindingsConfirmed.length > 0;
  const pAlert = pFindingsConfirmed.length > 0;
  const discriminated = vAlert && !pAlert;

  let classification = 'NO_ALERT';
  if (vAlert && !pAlert) classification = 'TRUE_DISCRIMINATION';
  else if (vAlert && pAlert) classification = 'PERSISTENT_ALERT';
  else if (!vAlert && !pAlert) classification = 'NO_ALERT';
  else if (!vAlert && pAlert) classification = 'INVERTED_ALERT';

  const row = {
    caseId: target.id,
    role: target.role,
    package: entry.packageName,
    cve: target.cve,
    rule: target.rule,
    file: target.file,
    vulnerableSha: entry.vulnerableSha.substring(0, 8),
    fixSha: entry.fixSha.substring(0, 8),
    vAlert,
    pAlert,
    discriminated,
    classification,
    vConfirmedCount: vFindingsConfirmed.length,
    pConfirmedCount: pFindingsConfirmed.length,
    vCandidateCount: vFindingsAll.filter(f => f.verdict === 'CANDIDATE').length,
    pCandidateCount: pFindingsAll.filter(f => f.verdict === 'CANDIDATE').length,
    vFindingsDetails: vFindingsAll.map(f => ({ line: f.line, verdict: f.verdict, snippet: f.snippet })),
    pFindingsDetails: pFindingsAll.map(f => ({ line: f.line, verdict: f.verdict, snippet: f.snippet }))
  };

  evaluatedPairs.push(row);
  fs.appendFileSync(resultsJsonl, JSON.stringify(row) + '\n');
  console.log(`[${target.role}] ${target.id} (${entry.packageName}): vConfirmed=${vAlert}, pConfirmed=${pAlert} -> ${classification} (${discriminated ? 'PASS' : 'HOLD'})`);
});

console.log('\n=== EVALUATING EXPANDED BENIGN CONTROLS (N=10) ===\n');

const evaluatedControls = [];
benignControls.forEach(ctrl => {
  const entry = manifest.entries.find(e => e.id === ctrl.pId);
  const repoDir = path.join(cloneBase, path.basename(entry.clonePath));

  const src = fetchFile(repoDir, entry.fixSha, ctrl.file);
  const allFindings = src ? analyzeFile(ctrl.file, src) : [];
  const confirmedFindings = allFindings.filter(f => f.verdict === 'CONFIRMED');
  const candidateFindings = allFindings.filter(f => f.verdict === 'CANDIDATE');

  const hasConfirmedAlert = confirmedFindings.length > 0;
  const classification = hasConfirmedAlert ? 'FALSE_POSITIVE' : 'TRUE_NEGATIVE';

  const row = {
    controlId: ctrl.id,
    package: ctrl.pkg,
    file: ctrl.file,
    sha: entry.fixSha.substring(0, 8),
    reason: ctrl.reason,
    hasConfirmedAlert,
    confirmedCount: confirmedFindings.length,
    candidateCount: candidateFindings.length,
    classification,
    confirmedFindings,
    candidateFindings
  };

  evaluatedControls.push(row);
  fs.appendFileSync(resultsJsonl, JSON.stringify(row) + '\n');
  console.log(`[Control] ${ctrl.id} (${ctrl.pkg}): confirmedAlerts=${hasConfirmedAlert} (Confirmed: ${confirmedFindings.length}, Candidate: ${candidateFindings.length}) -> ${classification}`);
});

// Compile Metrics
const calibPairs = evaluatedPairs.filter(p => p.role === 'CALIBRATION_REGRESSION');
const calibDiscrim = calibPairs.filter(p => p.discriminated).length;

const diagPairs = evaluatedPairs.filter(p => p.role === 'DIAGNOSTIC_REGRESSION');
const diagDiscrim = diagPairs.filter(p => p.discriminated).length;

const trueNegatives = evaluatedControls.filter(c => c.classification === 'TRUE_NEGATIVE').length;
const falsePositives = evaluatedControls.filter(c => c.classification === 'FALSE_POSITIVE').length;
const totalControls = evaluatedControls.length;

const summary = {
  phase: 'Phase Y2.2 — Sentinel Y v0.2 Semantic Hardening Evaluation',
  engineVersion: '0.2.0',
  evaluatedAt: new Date().toISOString(),
  calibrationRegressionSuite: {
    total: calibPairs.length,
    discriminated: calibDiscrim,
    discriminationRate: ((calibDiscrim / calibPairs.length) * 100).toFixed(2) + '%'
  },
  diagnosticRegressionSuite: {
    total: diagPairs.length,
    discriminated: diagDiscrim,
    discriminationRate: ((diagDiscrim / diagPairs.length) * 100).toFixed(2) + '%'
  },
  expandedBenignControls: {
    totalControls,
    trueNegatives,
    falsePositives,
    controlSpecificity: ((trueNegatives / totalControls) * 100).toFixed(2) + '%',
    controlFalseAlarmRate: ((falsePositives / totalControls) * 100).toFixed(2) + '%'
  },
  pairs: evaluatedPairs,
  controls: evaluatedControls
};

const metricsPath = path.resolve(__dirname, 'PHASE_Y2_2_METRICS.json');
fs.writeFileSync(metricsPath, JSON.stringify(summary, null, 2));

console.log('\n================ SUMMARY Y2.2 METRICS ================');
console.log(`Calibration Regression Rate (G7 Gate):     ${summary.calibrationRegressionSuite.discriminationRate} (${calibDiscrim}/${calibPairs.length})`);
console.log(`Diagnostic Regression Rate (json5 etc):    ${summary.diagnosticRegressionSuite.discriminationRate} (${diagDiscrim}/${diagPairs.length})`);
console.log(`Benign Negative Control Specificity (TN):  ${summary.expandedBenignControls.controlSpecificity} (${trueNegatives}/${totalControls})`);
console.log(`Benign Control False Alarm Rate (FPR):     ${summary.expandedBenignControls.controlFalseAlarmRate} (${falsePositives}/${totalControls})`);
console.log('======================================================\n');
