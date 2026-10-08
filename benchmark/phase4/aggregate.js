/**
 * Phase 4 — Aggregate
 * Reads PHASE4_RESULTS.jsonl and computes:
 *   - Overall: TP, TN, FP, FN, UNSCANNABLE, errors
 *   - Metrics: Recall (TPR), FPR, FNR, Precision, Accuracy, F1, OWASP Score
 *   - Per-category breakdown
 *   - Per-category OWASP Score
 * Writes PHASE4_AGGREGATE.json
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const { PHASE4_DIR, CATEGORY_CWE } = require('./config');

const RESULTS_PATH   = path.join(PHASE4_DIR, 'PHASE4_RESULTS.jsonl');
const AGGREGATE_PATH = path.join(PHASE4_DIR, 'PHASE4_AGGREGATE.json');

if (!fs.existsSync(RESULTS_PATH)) {
  console.error('FATAL: PHASE4_RESULTS.jsonl not found. Run runner.js first.');
  process.exit(1);
}

// ── Load results ─────────────────────────────────────────────────────────────
const lines = fs.readFileSync(RESULTS_PATH, 'utf8').trim().split('\n').filter(Boolean);
const results = lines.map((l, i) => {
  try { return JSON.parse(l); }
  catch { console.warn(`[aggregate] Skipping corrupt line ${i + 1}`); return null; }
}).filter(Boolean);

console.log(`[aggregate] Loaded ${results.length} result records`);

// ── Counters ──────────────────────────────────────────────────────────────────
const total = {
  TRUE_POSITIVE:    0,
  TRUE_NEGATIVE:    0,
  FALSE_POSITIVE:   0,
  FALSE_NEGATIVE:   0,
  SPECIALIST_ERROR: 0,
  TIMEOUT:          0,
  UNSCANNABLE:      0,
  ROUTING_ERROR:    0,
};

const byCategory = {};

for (const r of results) {
  const v = r.verdict;
  if (total[v] !== undefined) total[v]++;

  const cat = r.category || 'unknown';
  if (!byCategory[cat]) {
    byCategory[cat] = {
      cwe: CATEGORY_CWE[cat] || null,
      TRUE_POSITIVE:    0,
      TRUE_NEGATIVE:    0,
      FALSE_POSITIVE:   0,
      FALSE_NEGATIVE:   0,
      SPECIALIST_ERROR: 0,
      TIMEOUT:          0,
      UNSCANNABLE:      0,
    };
  }
  if (byCategory[cat][v] !== undefined) byCategory[cat][v]++;
}

// ── Metric helpers ────────────────────────────────────────────────────────────
function metrics(tp, tn, fp, fn) {
  const P = tp + fn;
  const N = tn + fp;
  const tpr = P > 0 ? tp / P : null;
  const fpr = N > 0 ? fp / N : null;
  const fnr = P > 0 ? fn / P : null;
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : null;
  const accuracy  = (tp + tn + fp + fn) > 0 ? (tp + tn) / (tp + tn + fp + fn) : null;
  const f1 = (precision !== null && tpr !== null && (precision + tpr) > 0)
    ? 2 * precision * tpr / (precision + tpr) : null;
  // OWASP Score = (TPR - FPR) × 100, range [-100, 100]
  const owaspScore = (tpr !== null && fpr !== null) ? (tpr - fpr) * 100 : null;
  return {
    P, N,
    TPR: tpr !== null ? +tpr.toFixed(6) : null,
    FPR: fpr !== null ? +fpr.toFixed(6) : null,
    FNR: fnr !== null ? +fnr.toFixed(6) : null,
    Precision: precision !== null ? +precision.toFixed(6) : null,
    Accuracy:  accuracy !== null  ? +accuracy.toFixed(6)  : null,
    F1:        f1 !== null        ? +f1.toFixed(6)        : null,
    OWASPScore: owaspScore !== null ? +owaspScore.toFixed(2) : null,
  };
}

// ── Overall metrics ───────────────────────────────────────────────────────────
const tp = total.TRUE_POSITIVE;
const tn = total.TRUE_NEGATIVE;
const fp = total.FALSE_POSITIVE;
const fn = total.FALSE_NEGATIVE;
const errors = total.SPECIALIST_ERROR + total.TIMEOUT + total.UNSCANNABLE + total.ROUTING_ERROR;

const overall = metrics(tp, tn, fp, fn);
const analyzable = tp + tn + fp + fn;

// ── Per-category metrics ──────────────────────────────────────────────────────
const categoryBreakdown = {};
for (const [cat, c] of Object.entries(byCategory)) {
  const m = metrics(c.TRUE_POSITIVE, c.TRUE_NEGATIVE, c.FALSE_POSITIVE, c.FALSE_NEGATIVE);
  categoryBreakdown[cat] = {
    cwe: c.cwe,
    counts: {
      TRUE_POSITIVE:    c.TRUE_POSITIVE,
      TRUE_NEGATIVE:    c.TRUE_NEGATIVE,
      FALSE_POSITIVE:   c.FALSE_POSITIVE,
      FALSE_NEGATIVE:   c.FALSE_NEGATIVE,
      SPECIALIST_ERROR: c.SPECIALIST_ERROR,
      TIMEOUT:          c.TIMEOUT,
      UNSCANNABLE:      c.UNSCANNABLE,
    },
    metrics: m,
  };
}

// ── Latency stats ─────────────────────────────────────────────────────────────
const msList = results.filter(r => typeof r.ms === 'number').map(r => r.ms).sort((a,b)=>a-b);
const medianMs = msList.length > 0 ? msList[Math.floor(msList.length / 2)] : null;
const meanMs   = msList.length > 0 ? msList.reduce((a,b)=>a+b,0)/msList.length : null;
const p95Ms    = msList.length > 0 ? msList[Math.floor(msList.length * 0.95)] : null;

// ── Assemble report ───────────────────────────────────────────────────────────
const aggregate = {
  generated:  new Date().toISOString(),
  phase:      4,
  corpus:     'OWASP Benchmark Java v1.2',
  totalRecords: results.length,
  verdicts: {
    TRUE_POSITIVE:    tp,
    TRUE_NEGATIVE:    tn,
    FALSE_POSITIVE:   fp,
    FALSE_NEGATIVE:   fn,
    SPECIALIST_ERROR: total.SPECIALIST_ERROR,
    TIMEOUT:          total.TIMEOUT,
    UNSCANNABLE:      total.UNSCANNABLE,
    ROUTING_ERROR:    total.ROUTING_ERROR,
  },
  analyzable,
  errors,
  overallMetrics: overall,
  latency: {
    medianMs: medianMs !== null ? +medianMs.toFixed(1) : null,
    meanMs:   meanMs   !== null ? +meanMs.toFixed(1)   : null,
    p95Ms:    p95Ms    !== null ? +p95Ms.toFixed(1)    : null,
    n:        msList.length,
  },
  categoryBreakdown,
};

fs.writeFileSync(AGGREGATE_PATH, JSON.stringify(aggregate, null, 2));
console.log(`[aggregate] Wrote → ${AGGREGATE_PATH}`);

// ── Human summary ─────────────────────────────────────────────────────────────
console.log('\n═══════════════════════════════════════════════════════════════');
console.log(' PHASE 4 — OWASP Benchmark Java v1.2  |  Semgrep p/java');
console.log('═══════════════════════════════════════════════════════════════');
console.log(`Total records:        ${results.length}`);
console.log(`Analyzable (TP+TN+FP+FN): ${analyzable}`);
console.log(`Errors/Unscannable:   ${errors}`);
console.log('');
console.log(`TRUE_POSITIVE  (TP):  ${tp}`);
console.log(`TRUE_NEGATIVE  (TN):  ${tn}`);
console.log(`FALSE_POSITIVE (FP):  ${fp}`);
console.log(`FALSE_NEGATIVE (FN):  ${fn}`);
console.log('');
console.log(`TPR (Recall):         ${overall.TPR !== null ? (overall.TPR*100).toFixed(2)+'%' : 'N/A'}`);
console.log(`FPR:                  ${overall.FPR !== null ? (overall.FPR*100).toFixed(2)+'%' : 'N/A'}`);
console.log(`Precision:            ${overall.Precision !== null ? (overall.Precision*100).toFixed(2)+'%' : 'N/A'}`);
console.log(`F1:                   ${overall.F1 !== null ? overall.F1.toFixed(4) : 'N/A'}`);
console.log(`Accuracy:             ${overall.Accuracy !== null ? (overall.Accuracy*100).toFixed(2)+'%' : 'N/A'}`);
console.log(`OWASP Score:          ${overall.OWASPScore !== null ? overall.OWASPScore.toFixed(2) : 'N/A'}`);
console.log('');
console.log('Per-category OWASP Scores:');
for (const [cat, v] of Object.entries(categoryBreakdown)) {
  const s = v.metrics.OWASPScore;
  console.log(`  ${cat.padEnd(14)} CWE-${String(v.cwe||'?').padEnd(4)}  ${s !== null ? s.toFixed(2) : 'N/A'}`);
}
console.log('═══════════════════════════════════════════════════════════════');
