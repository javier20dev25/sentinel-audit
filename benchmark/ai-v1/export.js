'use strict';
/**
 * Sentinel AI Benchmark — CSV comparison exporter
 * Reads runs.jsonl + judgments.jsonl and produces:
 *   - comparison.csv
 *   - summary.md (human-readable)
 */

const fs = require('fs');
const path = require('path');

const OUT_DIR = path.resolve(__dirname, '.');
const RUNS_FILE = path.join(OUT_DIR, 'runs.jsonl');
const JUDGMENTS_FILE = path.join(OUT_DIR, 'judgments.jsonl');
const SUMMARY_FILE = path.join(OUT_DIR, 'summary.json');

function readJsonl(fpath) {
  if (!fs.existsSync(fpath)) return [];
  return fs.readFileSync(fpath, 'utf8')
    .split('\n')
    .filter(l => l.trim())
    .map(l => { try { return JSON.parse(l); } catch (_) { return null; } })
    .filter(Boolean);
}

const runs = readJsonl(RUNS_FILE);
const judgments = readJsonl(JUDGMENTS_FILE);

if (!runs.length) {
  console.log('No runs found in runs.jsonl. Run runner.js first.');
  process.exit(0);
}

// CSV
const csvRows = [
  ['runId','caseId','mode','groundTruth','aiVerdict','tp','tn','fp','fn','unknown',
   'inputTokens','outputTokens','totalTokens','wallTimeMs','toolCalls','actualTokenMeasurement','error'].join(',')
];

for (const r of runs) {
  const j = judgments.find(x => x.runId === r.runId) || {};
  csvRows.push([
    r.runId, r.caseId, r.mode, j.groundTruth || '', r.overallVerdict || '',
    r.tp||0, r.tn||0, r.fp||0, r.fn||0, r.unknown||0,
    r.inputTokens||'', r.outputTokens||'', r.totalTokens||'',
    r.wallTimeMs||'', r.toolCalls||0, r.actualTokenMeasurement||'UNAVAILABLE',
    (r.error || '').replace(/,/g,'|'),
  ].join(','));
}

fs.writeFileSync(path.join(OUT_DIR, 'comparison.csv'), csvRows.join('\n'));
console.log('Wrote comparison.csv');

// Summary markdown
if (!fs.existsSync(SUMMARY_FILE)) { console.log('No summary.json found.'); process.exit(0); }
const summary = JSON.parse(fs.readFileSync(SUMMARY_FILE, 'utf8'));
const results = summary.results || {};

let md = `# Sentinel AI Benchmark v1 — Results\n\n`;
md += `**Completed:** ${summary.completedAt}\n`;
md += `**Model:** ${summary.model.provider}/${summary.model.model} temp=${summary.model.temperature}\n`;
md += `**Statistical Quality:** ${summary.statisticalQuality}\n`;
md += `**Corpus:** ${summary.corpus.malicious} malicious + ${summary.corpus.benign} benign + ${summary.corpus.semanticPair} semantic pair = ${summary.corpus.total} cases\n\n`;

md += `## Results by Mode\n\n`;
md += `| Metric | AI_ALONE | SENTINEL_ASSISTED | SENTINEL_AGENTIC |\n`;
md += `| :--- | ---: | ---: | ---: |\n`;

const modes = ['AI_ALONE', 'SENTINEL_ASSISTED', 'SENTINEL_AGENTIC'];
const rows = [
  ['TP', m => results[m] ? results[m].tp : 'N/A'],
  ['TN', m => results[m] ? results[m].tn : 'N/A'],
  ['FP', m => results[m] ? results[m].fp : 'N/A'],
  ['FN', m => results[m] ? results[m].fn : 'N/A'],
  ['UNKNOWN', m => results[m] ? results[m].unknown : 'N/A'],
  ['Precision', m => results[m] && results[m].precision !== null ? (results[m].precision*100).toFixed(1)+'%' : 'N/A'],
  ['Recall', m => results[m] && results[m].recall !== null ? (results[m].recall*100).toFixed(1)+'%' : 'N/A'],
  ['FPR', m => results[m] && results[m].fpr !== null ? (results[m].fpr*100).toFixed(1)+'%' : 'N/A'],
  ['FNR', m => results[m] && results[m].fnr !== null ? (results[m].fnr*100).toFixed(1)+'%' : 'N/A'],
  ['Total Tokens', m => results[m] ? results[m].totalTokens || 'N/A' : 'N/A'],
  ['Avg Tokens/run', m => results[m] ? results[m].avgTokensPerRun || 'N/A' : 'N/A'],
  ['Wall Time (ms)', m => results[m] ? results[m].totalWallTimeMs || 'N/A' : 'N/A'],
  ['Tool Calls', m => results[m] ? results[m].toolCalls || 0 : 'N/A'],
  ['Confirmed/1k tokens', m => results[m] && results[m].confirmedPer1kTokens !== null ? results[m].confirmedPer1kTokens : 'N/A'],
  ['Token Measurement', m => results[m] ? results[m].actualTokenMeasurement : 'N/A'],
];
for (const [label, fn] of rows) {
  md += `| ${label} | ${fn('AI_ALONE')} | ${fn('SENTINEL_ASSISTED')} | ${fn('SENTINEL_AGENTIC')} |\n`;
}

md += `\n## Semantic Pair Results\n\n`;
const spJudgments = judgments.filter(j => ['SP01a','SP01b'].includes(j.caseId));
if (spJudgments.length) {
  md += `| Case | Mode | Ground Truth | AI Verdict | Correct? |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- |\n`;
  for (const j of spJudgments.sort((a,b) => a.caseId.localeCompare(b.caseId))) {
    const correct = j.aiVerdict === (j.groundTruth === 'MALICIOUS' ? 'CONFIRMED' : 'BENIGN');
    md += `| ${j.caseId} | ${j.mode} | ${j.groundTruth} | ${j.aiVerdict} | ${correct ? '✅' : '❌'} |\n`;
  }
} else {
  md += '_Semantic pair not yet evaluated_\n';
}

md += `\n## Benchmark Status\n\n`;
md += `\`\`\`\nBENCHMARK_COMPLETE = ${summary.benchmarkComplete}\nACTUAL_TOKEN_MEASUREMENT = ${Object.values(results).some(r => r.actualTokenMeasurement === 'PASS') ? 'PASS' : 'UNAVAILABLE'}\n\`\`\`\n`;

fs.writeFileSync(path.join(OUT_DIR, 'summary.md'), md);
console.log('Wrote summary.md');
console.log('\n' + md);
