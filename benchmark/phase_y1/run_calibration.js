const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const CODEQL_BIN = 'C:\\Users\\sleyt\\AppData\\Local\\opencode\\tools\\codeql\\codeql.cmd';
const PACKS_DIR = 'C:\\Users\\sleyt\\.codeql\\packages';
const ROOT = path.resolve(__dirname, '../..');
const CALIB_DIR = path.resolve(__dirname, 'calibration');
const CLONES_DIR = path.resolve(__dirname, '../phase5/clones');
const MANIFEST = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../phase5/PHASE5_MANIFEST.json'), 'utf8'));

// 5 Selected cases
const selectedIds = ['P5-011', 'P5-030', 'P5-008', 'P5-001', 'P5-043'];
const cases = MANIFEST.entries.filter(e => selectedIds.includes(e.id));

const results = [];

function runCodeqlOnSnapshot(caseId, pkg, revision, sha, sourceDir) {
  const dbDir = path.join(CALIB_DIR, `db_${caseId}_${revision}`);
  const sarifDefault = path.join(CALIB_DIR, `codeql_${caseId}_${revision}_default.sarif`);
  const sarifSecExt = path.join(CALIB_DIR, `codeql_${caseId}_${revision}_secext.sarif`);

  try { fs.rmSync(dbDir, { recursive: true, force: true }); } catch {}

  console.log(`[CodeQL] Creating DB for ${caseId} (${pkg} @ ${revision} ${sha.slice(0, 8)})...`);
  const t0 = Date.now();
  
  // 1. Create DB (no-build)
  const dbRes = spawnSync(CODEQL_BIN, [
    'database', 'create', dbDir,
    '--language=javascript',
    '--source-root=' + sourceDir,
    '--overwrite'
  ], { encoding: 'utf8', timeout: 180000, windowsHide: true, shell: true });

  if (dbRes.status !== 0) {
    console.error(`[CodeQL] DB creation failed (code ${dbRes.status}): stdout: ${dbRes.stdout} | stderr: ${dbRes.stderr}`);
    return { error: 'DB_CREATION_FAILED', stderr: dbRes.stderr, stdout: dbRes.stdout };
  }

  // 2. Analyze with security-extended suite
  console.log(`[CodeQL] Analyzing with security-extended suite...`);
  const anRes = spawnSync(CODEQL_BIN, [
    'database', 'analyze', dbDir,
    'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
    '--format=sarif-latest',
    '--output=' + sarifSecExt,
    '--additional-packs=' + PACKS_DIR
  ], { encoding: 'utf8', timeout: 300000, windowsHide: true, shell: true });

  const durationMs = Date.now() - t0;
  let findings = [];
  if (fs.existsSync(sarifSecExt)) {
    try {
      const sarif = JSON.parse(fs.readFileSync(sarifSecExt, 'utf8'));
      findings = (sarif.runs && sarif.runs[0] && sarif.runs[0].results) || [];
    } catch (e) {
      console.error(`[CodeQL] Failed to parse SARIF: ${e.message}`);
    }
  }

  // Cleanup DB to save disk
  try { fs.rmSync(dbDir, { recursive: true, force: true }); } catch {}

  return {
    success: anRes.status === 0,
    durationMs,
    findingsCount: findings.length,
    sarifPath: sarifSecExt,
    findings
  };
}

function runSemgrepOnSnapshot(caseId, pkg, revision, sha, sourceDir) {
  const jsonPath = path.join(CALIB_DIR, `semgrep_${caseId}_${revision}.json`);
  console.log(`[Semgrep] Scanning ${caseId} (${pkg} @ ${revision})...`);
  const t0 = Date.now();

  const r = spawnSync('semgrep', [
    'scan',
    '--config=p/javascript',
    '--json',
    '--output=' + jsonPath,
    sourceDir
  ], { encoding: 'utf8', timeout: 180000, windowsHide: true });

  const durationMs = Date.now() - t0;
  let findings = [];
  if (fs.existsSync(jsonPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      findings = parsed.results || [];
    } catch (e) {}
  }

  return {
    status: r.status,
    durationMs,
    findingsCount: findings.length,
    jsonPath,
    findings
  };
}

for (const entry of cases) {
  const slug = entry.repoUrl.replace('https://github.com/', '').replace(/\//g, '_');
  const cloneDir = path.join(CLONES_DIR, slug);

  for (const [revision, sha] of [['vulnerable', entry.vulnerableSha], ['patched', entry.fixSha]]) {
    const wtDir = path.join(CALIB_DIR, `wt_${entry.id}_${revision}`);
    try { fs.rmSync(wtDir, { recursive: true, force: true }); } catch {}

    spawnSync('git', ['-C', cloneDir, 'worktree', 'add', '--force', '--detach', wtDir, sha], { windowsHide: true });

    // Execute reference tools
    const codeqlResult = runCodeqlOnSnapshot(entry.id, entry.packageName, revision, sha, wtDir);
    const semgrepResult = runSemgrepOnSnapshot(entry.id, entry.packageName, revision, sha, wtDir);

    // Remove worktree
    spawnSync('git', ['-C', cloneDir, 'worktree', 'remove', '--force', wtDir], { windowsHide: true });
    try { fs.rmSync(wtDir, { recursive: true, force: true }); } catch {}

    results.push({
      caseId: entry.id,
      package: entry.packageName,
      cwe: entry.cwe,
      revision,
      sha,
      affectedFiles: entry.affectedSourceFiles,
      codeql: {
        findingsCount: codeqlResult.findingsCount || 0,
        findings: (codeqlResult.findings || []).map(f => ({
          ruleId: f.ruleId,
          message: f.message ? f.message.text : '',
          locations: (f.locations || []).map(loc => loc.physicalLocation && loc.physicalLocation.artifactLocation ? loc.physicalLocation.artifactLocation.uri : '')
        }))
      },
      semgrep: {
        findingsCount: semgrepResult.findingsCount || 0,
        findings: (semgrepResult.findings || []).map(f => ({
          check_id: f.check_id,
          path: f.path,
          line: f.start ? f.start.line : 0
        }))
      }
    });
  }
}

fs.writeFileSync(path.resolve(__dirname, 'PHASE_Y1_CALIBRATION_RESULTS.json'), JSON.stringify({
  phase: 'Phase Y1 — Calibration Pilot (5 Representative Cases / 10 Snapshots)',
  completedAt: new Date().toISOString(),
  casesEvaluated: cases.length,
  results
}, null, 2));

console.log('Calibration pilot completed successfully.');
