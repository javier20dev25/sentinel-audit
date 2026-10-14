const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const CODEQL_BIN = 'C:\\Users\\sleyt\\AppData\\Local\\opencode\\tools\\codeql\\codeql.cmd';
const PACKS_DIR = 'C:\\Users\\sleyt\\.codeql\\packages';
const RUNS_DIR = path.resolve(__dirname, 'reference_runs');
const CLONES_DIR = path.resolve(__dirname, '../phase5/clones');
const MANIFEST = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../phase5/PHASE5_MANIFEST.json'), 'utf8'));

if (!fs.existsSync(RUNS_DIR)) fs.mkdirSync(RUNS_DIR, { recursive: true });

const missedIds = [
  'P5-002', 'P5-008', 'P5-010', 'P5-011', 'P5-013', 'P5-014',
  'P5-015', 'P5-016', 'P5-020', 'P5-021', 'P5-022', 'P5-027',
  'P5-029', 'P5-031', 'P5-033', 'P5-036', 'P5-037', 'P5-038',
  'P5-041', 'P5-042', 'P5-043', 'P5-044', 'P5-046', 'P5-047',
  'P5-048', 'P5-049'
];

const cohort = MANIFEST.entries.filter(e => missedIds.includes(e.id));
console.log(`Starting reference campaign over ${cohort.length} missed vulnerability cases (52 snapshots)...`);

const findingsJsonl = path.resolve(__dirname, 'PHASE_Y1_REFERENCE_FINDINGS.jsonl');
const semgrepJsonl = path.resolve(__dirname, 'PHASE_Y1_SEMGREP_RESULTS.jsonl');
fs.writeFileSync(findingsJsonl, '');
fs.writeFileSync(semgrepJsonl, '');

const matrix = [];

function runCodeql(caseId, pkg, revision, sha, sourceDir) {
  const dbDir = path.join(RUNS_DIR, `db_${caseId}_${revision}`);
  const sarifPath = path.join(RUNS_DIR, `codeql_${caseId}_${revision}.sarif`);
  try { fs.rmSync(dbDir, { recursive: true, force: true }); } catch {}

  const t0 = Date.now();
  const dbRes = spawnSync(CODEQL_BIN, [
    'database', 'create', dbDir,
    '--language=javascript',
    '--source-root=' + sourceDir,
    '--overwrite'
  ], { encoding: 'utf8', timeout: 180000, windowsHide: true, shell: true });

  if (dbRes.status !== 0) {
    return { error: 'DB_CREATION_FAILED', durationMs: Date.now() - t0, findings: [] };
  }

  const anRes = spawnSync(CODEQL_BIN, [
    'database', 'analyze', dbDir,
    'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
    '--format=sarif-latest',
    '--output=' + sarifPath,
    '--additional-packs=' + PACKS_DIR
  ], { encoding: 'utf8', timeout: 300000, windowsHide: true, shell: true });

  const durationMs = Date.now() - t0;
  let findings = [];
  if (fs.existsSync(sarifPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
      findings = (parsed.runs && parsed.runs[0] && parsed.runs[0].results) || [];
    } catch (e) {}
  }

  try { fs.rmSync(dbDir, { recursive: true, force: true }); } catch {}
  return { success: anRes.status === 0, durationMs, findings, sarifPath };
}

function runSemgrep(caseId, pkg, revision, sha, sourceDir) {
  const jsonPath = path.join(RUNS_DIR, `semgrep_${caseId}_${revision}.json`);
  const t0 = Date.now();

  const r = spawnSync('semgrep', [
    'scan',
    '--config=p/javascript',
    '--json',
    '--output=' + jsonPath,
    sourceDir
  ], { encoding: 'utf8', timeout: 180000, windowsHide: true, shell: true });

  const durationMs = Date.now() - t0;
  let findings = [];
  if (fs.existsSync(jsonPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      findings = parsed.results || [];
    } catch (e) {}
  }
  return { status: r.status, durationMs, findings, jsonPath };
}

for (let i = 0; i < cohort.length; i++) {
  const entry = cohort[i];
  console.log(`[${i+1}/${cohort.length}] Processing ${entry.id}: ${entry.packageName} (${entry.cwe})...`);

  const slug = entry.repoUrl.replace('https://github.com/', '').replace(/\//g, '_');
  const cloneDir = path.join(CLONES_DIR, slug);

  if (!fs.existsSync(cloneDir)) {
    console.error(`Clone missing for ${entry.repoUrl}`);
    continue;
  }

  const caseSummary = {
    id: entry.id,
    package: entry.packageName,
    advisoryId: entry.advisoryId,
    cves: entry.cves,
    cwe: entry.cwe,
    vulnerable: null,
    patched: null
  };

  for (const [revision, sha] of [['vulnerable', entry.vulnerableSha], ['patched', entry.fixSha]]) {
    const wtDir = path.join(RUNS_DIR, `wt_${entry.id}_${revision}`);
    try { fs.rmSync(wtDir, { recursive: true, force: true }); } catch {}

    const addRes = spawnSync('git', ['-C', cloneDir, 'worktree', 'add', '--force', '--detach', wtDir, sha], { windowsHide: true });
    if (addRes.status !== 0) {
      console.error(`Worktree add failed for ${entry.id} @ ${sha}`);
      continue;
    }

    const cql = runCodeql(entry.id, entry.packageName, revision, sha, wtDir);
    const sg = runSemgrep(entry.id, entry.packageName, revision, sha, wtDir);

    spawnSync('git', ['-C', cloneDir, 'worktree', 'remove', '--force', wtDir], { windowsHide: true });
    try { fs.rmSync(wtDir, { recursive: true, force: true }); } catch {}

    // Filter findings to affected source files
    const affectedSet = (entry.affectedSourceFiles || []).map(f => f.replace(/\\/g, '/').toLowerCase());
    
    const cqlInScope = (cql.findings || []).filter(f => {
      const locs = (f.locations || []).map(l => l.physicalLocation?.artifactLocation?.uri || '');
      return locs.some(loc => affectedSet.some(af => loc.toLowerCase().endsWith(af) || af.endsWith(loc.toLowerCase())));
    });

    const sgInScope = (sg.findings || []).filter(f => {
      const p = (f.path || '').replace(/\\/g, '/').toLowerCase();
      return affectedSet.some(af => p.endsWith(af) || af.endsWith(p));
    });

    const revSummary = {
      sha,
      codeqlFindingsCountTotal: (cql.findings || []).length,
      codeqlFindingsCountInScope: cqlInScope.length,
      codeqlInScopeRules: cqlInScope.map(f => f.ruleId),
      semgrepFindingsCountTotal: (sg.findings || []).length,
      semgrepFindingsCountInScope: sgInScope.length,
      semgrepInScopeRules: sgInScope.map(f => f.check_id)
    };

    if (revision === 'vulnerable') caseSummary.vulnerable = revSummary;
    else caseSummary.patched = revSummary;

    // Append to reference findings JSONL
    for (const f of cqlInScope) {
      fs.appendFileSync(findingsJsonl, JSON.stringify({
        caseId: entry.id,
        package: entry.packageName,
        cwe: entry.cwe,
        revision,
        sha,
        tool: 'codeql',
        ruleId: f.ruleId,
        message: f.message?.text,
        locations: f.locations,
        codeFlows: f.codeFlows
      }) + '\n');
    }

    for (const f of sgInScope) {
      fs.appendFileSync(semgrepJsonl, JSON.stringify({
        caseId: entry.id,
        package: entry.packageName,
        cwe: entry.cwe,
        revision,
        sha,
        tool: 'semgrep',
        check_id: f.check_id,
        path: f.path,
        start: f.start
      }) + '\n');
    }
  }

  matrix.push(caseSummary);
}

fs.writeFileSync(path.resolve(__dirname, 'PHASE_Y1_REFERENCE_MATRIX.json'), JSON.stringify({
  phase: 'Phase Y1 — Reference Analysis Matrix (N=26 Missed Vulnerability Cohort)',
  completedAt: new Date().toISOString(),
  totalCases: matrix.length,
  matrix
}, null, 2));

console.log('Reference campaign complete! Saved PHASE_Y1_REFERENCE_MATRIX.json.');
