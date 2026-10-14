const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('../../sentinel-y');

const targets = [
  {
    caseId: 'P5-013',
    package: 'deep-extend',
    weakness: 'CWE-1321 (Prototype Pollution)',
    rule: 'Y-PROTO-001',
    repo: 'unclechu_node-deep-extend',
    vSha: '9653940a',
    pSha: '9423fae8',
    file: 'lib/deep-extend.js'
  },
  {
    caseId: 'P5-015',
    package: 'mixin-deep',
    weakness: 'CWE-1321 (Prototype Pollution)',
    rule: 'Y-PROTO-001',
    repo: 'jonschlinkert_mixin-deep',
    vSha: '9925af76',
    pSha: '8f464c8c',
    file: 'index.js'
  },
  {
    caseId: 'P5-033',
    package: 'tough-cookie',
    weakness: 'CWE-1333 (ReDoS)',
    rule: 'Y-REDOS-001',
    repo: 'salesforce_tough-cookie',
    vSha: 'fcc8abfa',
    pSha: 'f1ed420a',
    file: 'lib/cookie.js'
  },
  {
    caseId: 'P5-041',
    package: 'cross-spawn',
    weakness: 'CWE-1333 (ReDoS)',
    rule: 'Y-REDOS-001',
    repo: 'moxystudio_node-cross-spawn',
    vSha: '9521e2da',
    pSha: '5ff3a07d',
    file: 'lib/util/escape.js'
  }
];

const results = [];
const jsonlPath = path.resolve(__dirname, 'PHASE_Y2_RESULTS.jsonl');
fs.writeFileSync(jsonlPath, '');

targets.forEach(t => {
  const clone = path.resolve(__dirname, '../phase5/clones', t.repo);
  const wtDir = path.resolve(__dirname, `wt_${t.caseId}`);

  // Test Vulnerable Revision
  try { fs.rmSync(wtDir, { recursive: true, force: true }); } catch {}
  require('child_process').spawnSync('git', ['-C', clone, 'worktree', 'add', '--force', '--detach', wtDir, t.vSha]);
  const vFilePath = path.join(wtDir, t.file);
  const vContent = fs.existsSync(vFilePath) ? fs.readFileSync(vFilePath, 'utf8') : '';
  const vFindings = analyzeFile(t.file, vContent);
  require('child_process').spawnSync('git', ['-C', clone, 'worktree', 'remove', '--force', wtDir]);

  // Test Patched Revision
  try { fs.rmSync(wtDir, { recursive: true, force: true }); } catch {}
  require('child_process').spawnSync('git', ['-C', clone, 'worktree', 'add', '--force', '--detach', wtDir, t.pSha]);
  const pFilePath = path.join(wtDir, t.file);
  const pContent = fs.existsSync(pFilePath) ? fs.readFileSync(pFilePath, 'utf8') : '';
  const pFindings = analyzeFile(t.file, pContent);
  require('child_process').spawnSync('git', ['-C', clone, 'worktree', 'remove', '--force', wtDir]);

  const vAlert = vFindings.some(f => f.ruleId === t.rule);
  const pAlert = pFindings.some(f => f.ruleId === t.rule);
  const discriminated = vAlert && !pAlert;

  const row = {
    caseId: t.caseId,
    package: t.package,
    weakness: t.weakness,
    rule: t.rule,
    vulnerableSha: t.vSha,
    patchedSha: t.pSha,
    file: t.file,
    vulnerableAlert: vAlert,
    patchedAlert: pAlert,
    discriminated,
    vFindingsCount: vFindings.length,
    pFindingsCount: pFindings.length,
    witness: vFindings[0]?.proofWitness || null
  };

  results.push(row);
  fs.appendFileSync(jsonlPath, JSON.stringify(row) + '\n');
});

const summary = {
  phase: 'Phase Y2 — Sentinel Y Prototype Differential Evaluation',
  evaluatedAt: new Date().toISOString(),
  totalCases: targets.length,
  discriminatedCount: results.filter(r => r.discriminated).length,
  discriminationRate: (results.filter(r => r.discriminated).length / targets.length) * 100 + '%',
  results
};

fs.writeFileSync(path.resolve(__dirname, 'PHASE_Y2_METRICS.json'), JSON.stringify(summary, null, 2));
console.log(`Differential evaluation complete: ${summary.discriminatedCount}/${targets.length} cases correctly discriminated (${summary.discriminationRate}).`);
