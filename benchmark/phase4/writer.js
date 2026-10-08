/**
 * Phase 4 — Writer
 * Reads PHASE4_AGGREGATE.json and PHASE4_ENVIRONMENT.json and writes
 * the final human-readable PHASE4_REPORT.md for the paper blueprint.
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const { PHASE4_DIR } = require('./config');

const AGG_PATH    = path.join(PHASE4_DIR, 'PHASE4_AGGREGATE.json');
const ENV_PATH    = path.join(PHASE4_DIR, 'PHASE4_ENVIRONMENT.json');
const REPORT_PATH = path.join(PHASE4_DIR, 'PHASE4_REPORT.md');

if (!fs.existsSync(AGG_PATH)) {
  console.error('FATAL: PHASE4_AGGREGATE.json not found. Run aggregate.js first.');
  process.exit(1);
}

const agg = JSON.parse(fs.readFileSync(AGG_PATH, 'utf8'));
const env = fs.existsSync(ENV_PATH) ? JSON.parse(fs.readFileSync(ENV_PATH, 'utf8')) : {};
const m = agg.overallMetrics;
const v = agg.verdicts;

function pct(x) { return x !== null ? (x * 100).toFixed(2) + '%' : 'N/A'; }
function n0(x)  { return x !== null ? x.toFixed(0) : 'N/A'; }
function f2(x)  { return x !== null ? x.toFixed(2) : 'N/A'; }

// Build category table
const catRows = Object.entries(agg.categoryBreakdown || {})
  .map(([cat, c]) => {
    const cm = c.metrics;
    return `| ${cat.padEnd(14)} | CWE-${String(c.cwe||'?').padEnd(3)} | ${c.counts.TRUE_POSITIVE} | ${c.counts.TRUE_NEGATIVE} | ${c.counts.FALSE_POSITIVE} | ${c.counts.FALSE_NEGATIVE} | ${pct(cm.TPR)} | ${pct(cm.FPR)} | ${f2(cm.OWASPScore)} |`;
  })
  .join('\n');

const report = `# Phase 4 — OWASP Benchmark Java v1.2

**Generated:** ${agg.generated}  
**Corpus:** ${agg.corpus} (N=${agg.totalRecords})  
**Specialist:** Semgrep \`${env.semgrepConfig || 'p/java'}\` v${env.semgrepVersion || '1.175.0'}  
**CodeQL:** ${env.codeqlVersion || 'NOT_INSTALLED'} (not available for this phase)  
**AI/LLM:** ${env.aiEnabled ? 'ENABLED' : 'DISABLED'} (LLM calls = 0)  
**Workers:** ${env.workers || 8} | **Timeout/file:** ${env.timeoutMs || 60000}ms  

---

## Environment Freeze

| Key | Value |
|---|---|
| audit SHA | \`${env.auditSha || 'N/A'}\` |
| semgrep | \`${env.semgrepVersion || 'N/A'}\` |
| config | \`${env.semgrepConfig || 'p/java'}\` |
| codeql | \`${env.codeqlVersion || 'NOT_INSTALLED'}\` |
| AI | \`${env.aiEnabled ? 'ENABLED' : 'DISABLED'}\` |
| build-mode | \`${env.buildMode || 'none'}\` (CodeQL flag, N/A) |

---

## Overall Results

| Metric | Value |
|---|---|
| Total test cases | **${agg.totalRecords}** |
| Analyzable (TP+TN+FP+FN) | **${agg.analyzable}** |
| Errors / Unscannable | **${agg.errors}** |
| TRUE_POSITIVE (TP) | **${v.TRUE_POSITIVE}** |
| TRUE_NEGATIVE (TN) | **${v.TRUE_NEGATIVE}** |
| FALSE_POSITIVE (FP) | **${v.FALSE_POSITIVE}** |
| FALSE_NEGATIVE (FN) | **${v.FALSE_NEGATIVE}** |
| SPECIALIST_ERROR | ${v.SPECIALIST_ERROR} |
| TIMEOUT | ${v.TIMEOUT} |
| UNSCANNABLE | ${v.UNSCANNABLE} |

## Detection Metrics

| Metric | Formula | Value |
|---|---|---|
| TPR (Recall) | TP/(TP+FN) | **${pct(m.TPR)}** |
| FPR | FP/(FP+TN) | **${pct(m.FPR)}** |
| FNR | FN/(TP+FN) | ${pct(m.FNR)} |
| Precision | TP/(TP+FP) | ${pct(m.Precision)} |
| Accuracy | (TP+TN)/N | ${pct(m.Accuracy)} |
| F1 | 2·P·R/(P+R) | ${f2(m.F1)} |
| **OWASP Score** | **(TPR−FPR)×100** | **${f2(m.OWASPScore)}** |

> [!NOTE] OWASP Score is the Youden index scaled to [−100, 100]. Baseline random classifier = 0. The raw Sentinel Cloud baseline on this corpus scored: TPR=94.4%, FPR=95.0%, OWASP Score≈−0.6.

---

## Latency

| Metric | Value |
|---|---|
| Median | ${agg.latency?.medianMs ?? 'N/A'} ms |
| Mean | ${agg.latency?.meanMs ?? 'N/A'} ms |
| P95 | ${agg.latency?.p95Ms ?? 'N/A'} ms |
| N (timed) | ${agg.latency?.n ?? 'N/A'} |

---

## Per-Category Breakdown

| Category | CWE | TP | TN | FP | FN | TPR | FPR | OWASP Score |
|---|---|---|---|---|---|---|---|---|
${catRows}

---

## Comparison: Raw Sentinel Cloud vs. Semgrep Java (Language-Aware Routing)

| Metric | Raw Cloud (Phase 2A baseline) | Semgrep Java (Phase 4) |
|---|---|---|
| Corpus | OWASP Java v1.2 (N=2,740) | OWASP Java v1.2 (N=2,740) |
| TP | 1,336 | ${v.TRUE_POSITIVE} |
| TN | 66 | ${v.TRUE_NEGATIVE} |
| FP | 1,259 | ${v.FALSE_POSITIVE} |
| FN | 79 | ${v.FALSE_NEGATIVE} |
| TPR | 94.4% | ${pct(m.TPR)} |
| FPR | 95.0% | ${pct(m.FPR)} |
| OWASP Score | ≈ −0.6 | ${f2(m.OWASPScore)} |

> [!IMPORTANT] The raw Cloud baseline is out-of-language-scope for Java: it applies JS/TS heuristics to Java source. The comparison isolates the routing benefit — not an engine quality improvement.

---

*Phase 4 frozen. Do not re-run without incrementing phase version and tagging corpus.*
`;

fs.writeFileSync(REPORT_PATH, report);
console.log(`[writer] Wrote → ${REPORT_PATH}`);
