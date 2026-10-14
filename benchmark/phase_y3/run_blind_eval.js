/**
 * Sentinel Y - Phase Y3 Blind Evaluation Runner
 * Automated Differential Evaluation on Package-Disjoint Corpus
 * Fully pre-registered against PHASE_Y3_BLIND_EVAL_PLAN.md
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { analyzeFile } = require('../../sentinel-y');

const manifestPath = path.resolve(__dirname, '../phase5/PHASE5_MANIFEST.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const cloneBase = path.resolve(__dirname, '../phase5/clones');
const codeqlMatrixPath = path.resolve(__dirname, '../phase_y1/PHASE_Y1_REFERENCE_MATRIX.json');
const codeqlMatrix = fs.existsSync(codeqlMatrixPath) ? JSON.parse(fs.readFileSync(codeqlMatrixPath, 'utf8')).matrix : [];

// 1. Panel A: Prototype Pollution (7 blind pairs)
const panelA = [
  { id: 'P5-007', rule: 'Y-PROTO-001', weakness: 'CWE-1321 (Prototype Pollution)', file: 'lib/document.js' },
  { id: 'P5-011', rule: 'Y-PROTO-001', weakness: 'CWE-1321 (Prototype Pollution)', file: 'index.js' },
  { id: 'P5-014', rule: 'Y-PROTO-001', weakness: 'CWE-1321 (Prototype Pollution)', file: 'index.js' },
  { id: 'P5-016', rule: 'Y-PROTO-001', weakness: 'CWE-1321 (Prototype Pollution)', file: 'index.js' },
  { id: 'P5-018', rule: 'Y-PROTO-001', weakness: 'CWE-1321 (Prototype Pollution)', file: 'lodash.js' },
  { id: 'P5-029', rule: 'Y-PROTO-001', weakness: 'CWE-1321 (Prototype Pollution)', file: 'src/parse.js' },
  { id: 'P5-038', rule: 'Y-PROTO-001', weakness: 'CWE-1321 (Prototype Pollution)', file: 'lib/internal/iterator.js' }
];

// 2. Panel B: ReDoS (6 blind pairs)
const panelB = [
  { id: 'P5-020', rule: 'Y-REDOS-001', weakness: 'CWE-1333 (ReDoS)', file: 'src/lib/parse/regex.js' },
  { id: 'P5-027', rule: 'Y-REDOS-001', weakness: 'CWE-1333 (ReDoS)', file: 'index.js' },
  { id: 'P5-028', rule: 'Y-REDOS-001', weakness: 'CWE-1333 (ReDoS)', file: 'index.js' },
  { id: 'P5-030', rule: 'Y-REDOS-001', weakness: 'CWE-1333 (ReDoS)', file: 'semver.js' },
  { id: 'P5-031', rule: 'Y-REDOS-001', weakness: 'CWE-1333 (ReDoS)', file: 'semver.js' },
  { id: 'P5-039', rule: 'Y-REDOS-001', weakness: 'CWE-1333 (ReDoS)', file: 'src/node.js' }
];

// 3. Panel C: Benign Negative Controls (7 clean packages)
const panelC = [
  { id: 'CTRL-01', pId: 'P5-019', pkg: 'axios', file: 'lib/adapters/http.js' },
  { id: 'CTRL-02', pId: 'P5-023', pkg: 'node-fetch', file: 'src/index.js' },
  { id: 'CTRL-03', pId: 'P5-010', pkg: 'jsonwebtoken', file: 'index.js' },
  { id: 'CTRL-04', pId: 'P5-012', pkg: 'nodemailer', file: 'lib/nodemailer.js' },
  { id: 'CTRL-05', pId: 'P5-025', pkg: 'ejs', file: 'lib/ejs.js' },
  { id: 'CTRL-06', pId: 'P5-042', pkg: 'body-parser', file: 'lib/types/urlencoded.js' },
  { id: 'CTRL-07', pId: 'P5-045', pkg: 'socket.io', file: 'lib/manager.js' }
];

function fetchFile(repoDir, sha, file) {
  try {
    return execSync(`git show ${sha}:${file}`, { cwd: repoDir, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
  } catch (e) {
    return null;
  }
}

const evaluatedPairs = [];
const evaluatedControls = [];
const allRows = [];
const jsonlPath = path.resolve(__dirname, 'PHASE_Y3_RESULTS.jsonl');
fs.writeFileSync(jsonlPath, '');

console.log('=== EXECUTING PHASE Y3 BLIND EVALUATION ===\n');

// Evaluate Panels A & B
const testPairs = [...panelA.map(p => ({ ...p, panel: 'A (Proto)' })), ...panelB.map(p => ({ ...p, panel: 'B (ReDoS)' }))];

testPairs.forEach(target => {
  const entry = manifest.entries.find(e => e.id === target.id);
  const repoDir = path.join(cloneBase, path.basename(entry.clonePath));

  const vSrc = fetchFile(repoDir, entry.vulnerableSha, target.file);
  const pSrc = fetchFile(repoDir, entry.fixSha, target.file);

  const vFindings = vSrc ? analyzeFile(target.file, vSrc).filter(f => f.ruleId === target.rule) : [];
  const pFindings = pSrc ? analyzeFile(target.file, pSrc).filter(f => f.ruleId === target.rule) : [];

  const vAlert = vFindings.length > 0;
  const pAlert = pFindings.length > 0;
  const discriminated = vAlert && !pAlert;

  // Determine Pre-registered Category
  let category = 'UNKNOWN';
  if (vAlert && !pAlert) category = 'TD'; // True Discrimination
  else if (!vAlert && !pAlert) category = 'FN'; // False Negative (missed)
  else if (vAlert && pAlert) category = 'PFA'; // Persistent False Alarm
  else if (!vAlert && pAlert) category = 'ID'; // Inverted Discrimination

  // Lookup CodeQL baseline in matrix
  const cqlEntry = codeqlMatrix.find(m => m.id === target.id);
  const cqlVulnAlert = cqlEntry ? (cqlEntry.vulnerable && cqlEntry.vulnerable.codeqlFindingsCountInScope > 0) : null;
  const cqlPatchAlert = cqlEntry ? (cqlEntry.patched && cqlEntry.patched.codeqlFindingsCountInScope > 0) : null;
  const cqlDiscriminated = (cqlVulnAlert === true && cqlPatchAlert === false);

  const row = {
    caseId: target.id,
    panel: target.panel,
    package: entry.packageName,
    cve: entry.cves[0],
    rule: target.rule,
    file: target.file,
    vulnerableSha: entry.vulnerableSha.substring(0, 8),
    fixSha: entry.fixSha.substring(0, 8),
    vAlert,
    pAlert,
    discriminated,
    category,
    vFindingCount: vFindings.length,
    pFindingCount: pFindings.length,
    codeqlBaseline: {
      vulnAlert: cqlVulnAlert,
      patchAlert: cqlPatchAlert,
      discriminated: cqlDiscriminated
    },
    sampleFinding: vFindings[0] || null
  };

  evaluatedPairs.push(row);
  allRows.push(row);
  fs.appendFileSync(jsonlPath, JSON.stringify(row) + '\n');
  console.log(`[${target.panel}] ${target.id} (${entry.packageName} ${entry.cves[0]}): vAlert=${vAlert}, pAlert=${pAlert} -> ${category} (CodeQL: ${cqlDiscriminated ? 'TD' : 'FAIL'})`);
});

console.log('\n=== EXECUTING BENIGN CONTROLS (PANEL C) ===\n');

// Evaluate Panel C
panelC.forEach(ctrl => {
  const entry = manifest.entries.find(e => e.id === ctrl.pId);
  const repoDir = path.join(cloneBase, path.basename(entry.clonePath));

  const src = fetchFile(repoDir, entry.fixSha, ctrl.file);
  const findings = src ? analyzeFile(ctrl.file, src) : [];
  const hasAlert = findings.length > 0;
  const category = hasAlert ? 'FP' : 'TN';

  const row = {
    controlId: ctrl.id,
    panel: 'C (Control)',
    package: ctrl.pkg,
    file: ctrl.file,
    sha: entry.fixSha.substring(0, 8),
    hasAlert,
    findingCount: findings.length,
    category,
    findings
  };

  evaluatedControls.push(row);
  allRows.push(row);
  fs.appendFileSync(jsonlPath, JSON.stringify(row) + '\n');
  console.log(`[Control] ${ctrl.id} (${ctrl.pkg}): alerts=${hasAlert} (${findings.length} findings) -> ${category}`);
});

// Compute Metrics
const tdCount = evaluatedPairs.filter(p => p.category === 'TD').length;
const pfaCount = evaluatedPairs.filter(p => p.category === 'PFA').length;
const fnCount = evaluatedPairs.filter(p => p.category === 'FN').length;
const idCount = evaluatedPairs.filter(p => p.category === 'ID').length;
const totalBlindPairs = evaluatedPairs.length;

const tnControlCount = evaluatedControls.filter(c => c.category === 'TN').length;
const fpControlCount = evaluatedControls.filter(c => c.category === 'FP').length;
const totalControls = evaluatedControls.length;

const pdr = ((tdCount / totalBlindPairs) * 100).toFixed(2) + '%';
const pfar = ((pfaCount / totalBlindPairs) * 100).toFixed(2) + '%';
const fnr = ((fnCount / totalBlindPairs) * 100).toFixed(2) + '%';
const fprCtrl = ((fpControlCount / totalControls) * 100).toFixed(2) + '%';

// CodeQL comparison on same 13 pairs
const cqlTdCount = evaluatedPairs.filter(p => p.codeqlBaseline.discriminated).length;
const cqlPdr = ((cqlTdCount / totalBlindPairs) * 100).toFixed(2) + '%';

const summary = {
  phase: 'Phase Y3 — Blind Evaluation on Package-Disjoint Corpus',
  evaluatedAt: new Date().toISOString(),
  engine: 'Sentinel Y v0.1.0-alpha',
  totalBlindPairs,
  breakdownByPanel: {
    panelA_proto: {
      total: panelA.length,
      discriminated: evaluatedPairs.filter(p => p.panel.includes('Proto') && p.category === 'TD').length
    },
    panelB_redos: {
      total: panelB.length,
      discriminated: evaluatedPairs.filter(p => p.panel.includes('ReDoS') && p.category === 'TD').length
    }
  },
  pairedMetrics: {
    trueDiscrimination: tdCount,
    persistentFalseAlarm: pfaCount,
    falseNegative: fnCount,
    invertedDiscrimination: idCount,
    pairedDiscriminationRate: pdr,
    persistentFalseAlarmRate: pfar,
    falseNegativeRate: fnr
  },
  controlMetrics: {
    totalControls,
    trueNegatives: tnControlCount,
    falsePositives: fpControlCount,
    falsePositiveRateControls: fprCtrl
  },
  headToHeadVsCodeQL: {
    sentinelY_discriminated: tdCount,
    sentinelY_rate: pdr,
    codeql_discriminated: cqlTdCount,
    codeql_rate: cqlPdr,
    deltaPdr: (((tdCount - cqlTdCount) / totalBlindPairs) * 100).toFixed(2) + '%'
  },
  blindPairs: evaluatedPairs,
  controls: evaluatedControls
};

const metricsPath = path.resolve(__dirname, 'PHASE_Y3_METRICS.json');
fs.writeFileSync(metricsPath, JSON.stringify(summary, null, 2));

console.log('\n================ SUMMARY METRICS ================');
console.log(`Blind Paired Discrimination Rate (Sentinel Y): ${pdr} (${tdCount}/${totalBlindPairs})`);
console.log(`Blind Paired Discrimination Rate (CodeQL):     ${cqlPdr} (${cqlTdCount}/${totalBlindPairs})`);
console.log(`Delta vs CodeQL on Blind Pairs:                ${summary.headToHeadVsCodeQL.deltaPdr}`);
console.log(`Benign Negative Control Specificity (TN Rate): ${((tnControlCount / totalControls) * 100).toFixed(2)}% (${tnControlCount}/${totalControls})`);
console.log(`Benign Control False Alarm Rate (FPR):         ${fprCtrl} (${fpControlCount}/${totalControls})`);
console.log('=================================================\n');
