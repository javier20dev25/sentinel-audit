'use strict';
// Consolidated acceptance evidence table across the five pinned repositories.
const fs = require('fs');
const path = require('path');

const base = process.argv[2];
const pins = {
  express: '9a34acf03cb818ff3f8bc40e44176e277a25cbb9',
  fastify: 'bc25b7499acedb803ef3cef644d0d56cf4e7c725',
  svelte: 'f90853565966bc0bab57c99fe7d669a91bef0f4c',
  flags: 'c3026fe78b527f8c4300f444751ef4f9325db50e',
  swr: '9ed1240a4cf799e316a793c22c6800cc6482d389',
};

function newestExecution(root) {
  if (!fs.existsSync(root)) return null;
  const dirs = fs.readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name.startsWith('exec-'))
    .map((d) => path.join(root, d.name))
    .filter((p) => fs.existsSync(path.join(p, 'expediente.json')))
    .sort();
  return dirs.length ? dirs[dirs.length - 1] : null;
}

const rows = [];
for (const [name, pin] of Object.entries(pins)) {
  const dir = newestExecution(path.join(base, name, name));
  if (!dir) { rows.push({ name, pin, error: 'no execution found' }); continue; }
  const e = JSON.parse(fs.readFileSync(path.join(dir, 'expediente.json'), 'utf8'));
  const tools = {};
  for (const [tool, t] of Object.entries(e.tools || {})) {
    tools[tool] = { status: t.status, findings: t.findingCount == null ? 0 : t.findingCount, version: (t.availability && t.availability.version) || t.version || null };
  }
  rows.push({
    name, pin, dir,
    commitMatches: e.commit === pin,
    commit: e.commit,
    pipelineStatus: e.pipelineStatus,
    verdict: e.auditVerdict && e.auditVerdict.verdict,
    analysisState: e.auditVerdict && e.auditVerdict.analysisState,
    canClaimClean: e.auditVerdict && e.auditVerdict.canClaimClean,
    candidates: (e.candidates || []).length,
    observations: (e.observations || []).length,
    cleanup: e.cleanup && e.cleanup.cleanupStatus,
    toolCount: Object.keys(tools).length,
    tools,
  });
}

fs.writeFileSync(path.join(base, 'acceptance-summary.json'), JSON.stringify({ generatedAt: new Date().toISOString(), rows }, null, 2));

const pad = (s, n) => String(s == null ? '-' : s).padEnd(n);
console.log(pad('repo', 9) + pad('pinOK', 7) + pad('pipeline', 10) + pad('verdict', 18) + pad('state', 18) + pad('clean?', 8) + pad('cand', 5) + pad('obs', 5) + pad('cleanup', 8) + 'exit');
for (const r of rows) {
  if (r.error) { console.log(pad(r.name, 9) + 'ERROR: ' + r.error); continue; }
  const exit = r.canClaimClean ? 0 : r.candidates > 0 ? 1 : 2;
  console.log(pad(r.name, 9) + pad(r.commitMatches, 7) + pad(r.pipelineStatus, 10) + pad(r.verdict, 18) + pad(r.analysisState, 18) + pad(r.canClaimClean, 8) + pad(r.candidates, 5) + pad(r.observations, 5) + pad(r.cleanup, 8) + exit);
}
console.log('');
for (const r of rows) {
  if (r.error) continue;
  const parts = Object.entries(r.tools).map(([k, v]) => `${k}=${v.status}/${v.findings}${v.version ? '@' + v.version : ''}`);
  console.log(pad(r.name, 9) + parts.join('  '));
}
