'use strict';
// Why each repository did or did not promote candidates.
const fs = require('fs');
const path = require('path');

const base = process.argv[2];
const repos = ['express', 'fastify', 'svelte', 'flags', 'swr'];

function newestExecution(root) {
  const dirs = fs.readdirSync(root, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name.startsWith('exec-'))
    .map((d) => path.join(root, d.name))
    .filter((p) => fs.existsSync(path.join(p, 'expediente.json')))
    .sort();
  return dirs[dirs.length - 1];
}

let grand = { signals: 0, findings: 0, candidates: 0, observations: 0 };
for (const name of repos) {
  const dir = newestExecution(path.join(base, name, name));
  const e = JSON.parse(fs.readFileSync(path.join(dir, 'expediente.json'), 'utf8'));

  const signals = (e.tools.sentinel && e.tools.sentinel.findingCount) || 0;
  const perTool = {};
  let findings = 0;
  for (const [tool, t] of Object.entries(e.tools)) {
    if (tool === 'sentinel') continue;
    const n = t.findingCount || 0;
    perTool[tool] = `${t.status} ${n}`;
    findings += n;
  }
  const candidates = (e.candidates || []).length;
  const observations = (e.observations || []).length;
  grand.signals += signals; grand.findings += findings;
  grand.candidates += candidates; grand.observations += observations;

  console.log(`\n=== ${name} ===`);
  console.log(`  Cloud signals (ACTIONABLE+): ${signals}`);
  console.log(`  Specialist findings: ${findings}  [${Object.entries(perTool).map(([k, v]) => k + ' ' + v).join(' | ')}]`);
  console.log(`  -> candidates: ${candidates}   observations: ${observations}`);

  const why = {};
  for (const o of e.observations || []) {
    const key = `${o.scope || o.classification || '?'} / ${o.disposition || o.reason || o.status || '?'}`;
    why[key] = (why[key] || 0) + 1;
  }
  for (const [k, n] of Object.entries(why).sort((a, b) => b[1] - a[1]).slice(0, 6)) {
    console.log(`     ${String(n).padStart(4)}x  ${k}`);
  }
}
console.log('\n=== TOTAL ===');
console.log(`  Cloud signals: ${grand.signals}`);
console.log(`  Specialist findings: ${grand.findings}`);
console.log(`  Candidates: ${grand.candidates}   Observations retained: ${grand.observations}`);
