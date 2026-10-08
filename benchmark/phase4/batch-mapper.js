/**
 * Phase 4 — Batch Results Mapper
 * Maps the global semgrep_raw_results.json findings across the 2,740
 * test cases in PHASE4_MANIFEST.json and writes:
 *   - PHASE4_RESULTS.jsonl
 */
'use strict';

const fs = require('fs');
const path = require('path');
const {
  PHASE4_DIR,
  VERDICT,
  AI_ENABLED
} = require('./config');

const MANIFEST_PATH = path.join(PHASE4_DIR, 'PHASE4_MANIFEST.json');
const RAW_RESULTS_PATH = path.join(PHASE4_DIR, 'semgrep_raw_results.json');
const RESULTS_PATH = path.join(PHASE4_DIR, 'PHASE4_RESULTS.jsonl');

if (!fs.existsSync(MANIFEST_PATH)) {
  console.error('FATAL: Manifest not found');
  process.exit(1);
}
if (!fs.existsSync(RAW_RESULTS_PATH)) {
  console.error('FATAL: Raw semgrep results not found');
  process.exit(1);
}

console.log('[mapper] Loading manifest...');
const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
const entries = manifest.entries;

console.log('[mapper] Loading raw semgrep results...');
const rawData = JSON.parse(fs.readFileSync(RAW_RESULTS_PATH, 'utf8'));
const semgrepResults = rawData.results || [];
console.log(`[mapper] Total raw Semgrep findings: ${semgrepResults.length}`);

// Map findings by normalized file path or testName
const findingsByTestName = new Map();

for (const r of semgrepResults) {
  // r.path is like "C:\\Users\\...\\BenchmarkTest00001.java"
  const fileName = path.basename(r.path || '');
  const testName = fileName.replace(/\.java$/i, '');
  if (!findingsByTestName.has(testName)) {
    findingsByTestName.set(testName, []);
  }
  findingsByTestName.get(testName).push({
    rule: r.check_id,
    file: r.path,
    line: r.start && r.start.line,
    severity: (r.extra && r.extra.severity) ? r.extra.severity.toUpperCase() : 'UNKNOWN',
    message: r.extra && r.extra.message ? r.extra.message.slice(0, 200) : ''
  });
}

function classify(vulnerable, flagged) {
  if (vulnerable && flagged) return VERDICT.TRUE_POSITIVE;
  if (!vulnerable && flagged) return VERDICT.FALSE_POSITIVE;
  if (vulnerable && !flagged) return VERDICT.FALSE_NEGATIVE;
  return VERDICT.TRUE_NEGATIVE;
}

const counters = {
  TRUE_POSITIVE: 0,
  TRUE_NEGATIVE: 0,
  FALSE_POSITIVE: 0,
  FALSE_NEGATIVE: 0,
  UNSCANNABLE: 0,
  SPECIALIST_ERROR: 0
};

const lines = [];
for (const entry of entries) {
  const { testName, category, vulnerable, cwe, file, sha256 } = entry;
  const findings = findingsByTestName.get(testName) || [];
  const flagged = findings.length > 0;
  const verdict = classify(vulnerable, flagged);

  counters[verdict]++;

  const record = {
    testName,
    category,
    vulnerable,
    cwe,
    file,
    sha256,
    language: 'java',
    specialist: 'semgrep',
    verdict,
    flagged,
    findings,
    ms: 71, // average batch ms (194.2s / 2740 files)
    ts: new Date().toISOString()
  };

  lines.push(JSON.stringify(record));
}

fs.writeFileSync(RESULTS_PATH, lines.join('\n') + '\n', 'utf8');
console.log(`[mapper] Successfully wrote ${lines.length} records to ${RESULTS_PATH}`);
console.log('[mapper] Summary:');
console.log(`  TRUE_POSITIVE:  ${counters.TRUE_POSITIVE}`);
console.log(`  TRUE_NEGATIVE:  ${counters.TRUE_NEGATIVE}`);
console.log(`  FALSE_POSITIVE: ${counters.FALSE_POSITIVE}`);
console.log(`  FALSE_NEGATIVE: ${counters.FALSE_NEGATIVE}`);
