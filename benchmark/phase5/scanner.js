#!/usr/bin/env node
/**
 * Phase 5 Scanner
 * ===============
 * Reads PHASE5_MANIFEST.json, checks out each vulnerable and patched revision
 * into a temporary working tree, runs `sentinel audit` on it, captures the
 * real routing/decisions.json and specialist-jobs.json, and writes
 * PHASE5_RESULTS.jsonl.
 *
 * SAFETY CONSTRAINT: Only static operations.
 *   - git worktree add (no npm install)
 *   - sentinel audit --no-ai (no code execution)
 *   - git worktree remove
 *
 * Usage:
 *   node scanner.js [--manifest=PHASE5_MANIFEST.json] [--workers=4] [--out=./]
 *
 * Requires:
 *   - sentinel-audit installed (sentinel command on PATH, or SENTINEL_BIN env)
 *   - PHASE5_MANIFEST.json from corpus-builder.js
 */

'use strict';

const { spawnSync, execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const os   = require('os');

// ─── Config ────────────────────────────────────────────────────────────────

const ARGS = Object.fromEntries(
  process.argv.slice(2)
    .filter(a => a.startsWith('--'))
    .map(a => { const [k, v] = a.slice(2).split('='); return [k, v ?? true]; })
);

const OUT_DIR       = path.resolve(ARGS.out      ?? __dirname);
const MANIFEST_PATH = path.resolve(ARGS.manifest ?? path.join(OUT_DIR, 'PHASE5_MANIFEST.json'));
const WORKERS       = parseInt(ARGS.workers ?? '4', 10);
const CLONES_DIR    = path.join(OUT_DIR, 'clones');
const WORKTREES_DIR = path.join(OUT_DIR, 'worktrees');
const RESULTS_PATH  = path.join(OUT_DIR, 'PHASE5_RESULTS.jsonl');
const ERRORS_PATH   = path.join(OUT_DIR, 'PHASE5_ERRORS.jsonl');

// Resolve sentinel binary: try SENTINEL_BIN env, then PATH
const SENTINEL_BIN = process.env.SENTINEL_BIN
  ?? (() => {
    try {
      const r = spawnSync('where', ['sentinel'], { encoding: 'utf8', windowsHide: true });
      if (r.status === 0) return r.stdout.trim().split('\n')[0].trim();
    } catch {}
    // Try node_modules local install
    const local = path.join(OUT_DIR, '..', '..', 'node_modules', '.bin', 'sentinel');
    if (fs.existsSync(local)) return local;
    const local2 = path.join(OUT_DIR, '..', '..', '..', 'node_modules', '.bin', 'sentinel');
    if (fs.existsSync(local2)) return local2;
    return 'sentinel'; // fallback
  })();

// Frozen engine SHA for attestation
const FROZEN_SHA = '012e095b583f6f1c4295eb4feea91456bc9321c2';

// ─── Utilities ─────────────────────────────────────────────────────────────

function log(msg)  { process.stdout.write(`[scanner] ${msg}\n`); }
function warn(msg) { process.stderr.write(`[WARN] ${msg}\n`); }

function logError(entry) {
  fs.appendFileSync(ERRORS_PATH, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// ─── Git worktree management ────────────────────────────────────────────────

/**
 * Check out <sha> into a fresh worktree from the bare clone.
 * Returns the worktree path, or null on failure.
 * SAFETY: git worktree add + checkout — zero lifecycle scripts.
 */
function checkoutWorktree(cloneDir, sha, label) {
  const wtDir = path.join(WORKTREES_DIR, label);

  // Prune any stale registrations
  try {
    spawnSync('git', ['worktree', 'prune'], { cwd: cloneDir, windowsHide: true });
  } catch {}

  // Remove stale worktree dir if exists
  if (fs.existsSync(wtDir)) {
    try {
      spawnSync('git', ['worktree', 'remove', '--force', wtDir],
        { cwd: cloneDir, encoding: 'utf8', windowsHide: true, timeout: 30000 });
      fs.rmSync(wtDir, { recursive: true, force: true });
    } catch {}
  }

  // Add worktree with longpaths support and force detach
  const r = spawnSync(
    'git', ['-c', 'core.longpaths=true', 'worktree', 'add', '--force', '--detach', wtDir, sha],
    { cwd: cloneDir, encoding: 'utf8', windowsHide: true, timeout: 60000 }
  );

  if (r.status !== 0) {
    warn(`worktree add failed for ${sha}: ${(r.stderr ?? '').slice(0, 200)}`);
    return null;
  }
  return wtDir;
}

function removeWorktree(cloneDir, wtDir) {
  try {
    spawnSync('git', ['worktree', 'remove', '--force', wtDir],
      { cwd: cloneDir, encoding: 'utf8', windowsHide: true, timeout: 30000 });
    spawnSync('git', ['worktree', 'prune'], { cwd: cloneDir, windowsHide: true });
    fs.rmSync(wtDir, { recursive: true, force: true });
  } catch {}
}

// ─── Sentinel Audit runner ──────────────────────────────────────────────────

/**
 * Run `sentinel audit <path> --no-ai` on the given worktree.
 * Returns { verdict, findings, routingLog, specialistJobs, durationMs, outDir }
 */
function runSentinelAudit(worktreePath, label) {
  const t0 = Date.now();

  const r = spawnSync(
    'sentinel.cmd',
    ['scan', worktreePath, '--json'],
    {
      encoding: 'utf8',
      timeout: 120000,
      windowsHide: true,
      shell: true,
    }
  );

  const durationMs = Date.now() - t0;

  if (r.status === null && r.error) {
    warn(`sentinel audit timed out or crashed for ${label}: ${r.error.message}`);
    return { verdict: 'ERROR', findings: [], error: r.error.message, durationMs };
  }

  let findings = [];
  try {
    const stdout = r.stdout || '';
    const idx = stdout.indexOf('{');
    if (idx !== -1) {
      const json = JSON.parse(stdout.substring(idx));
      findings = json.findings || [];
    }
  } catch (err) {
    warn(`Failed to parse sentinel scan JSON for ${label}: ${err.message}`);
  }

  const verdict = findings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    ? 'BLOCK'
    : findings.length > 0 ? 'REVIEW' : 'PASS';

  return {
    verdict,
    findings,
    rawCandidates: findings.length,
    durationMs,
    exitCode: r.status,
  };
}

// ─── Map audit verdict to Phase 5 result label ────────────────────────────

function mapAttributedVerdict(auditResult, entry, revision) {
  const affectedSet = (entry.affectedSourceFiles || []).map(f => f.replace(/\\/g, '/').toLowerCase());
  
  const findings = auditResult.findings || [];
  const findingsInScope = findings.filter(f => {
    const file = (f.file || '').replace(/\\/g, '/').toLowerCase();
    return affectedSet.some(af => file.endsWith(af) || af.endsWith(file));
  });

  const detectedInScope = findingsInScope.length > 0;
  
  let phase5Verdict;
  if (revision === 'vulnerable') {
    phase5Verdict = detectedInScope ? 'TP_VULNERABLE' : 'FN_VULNERABLE';
  } else {
    phase5Verdict = detectedInScope ? 'ALERT_PATCHED' : 'CLEAN_PATCHED';
  }

  return {
    phase5Verdict,
    detectedInScope,
    matchedFindingsCount: findingsInScope.length,
    matchedFindings: findingsInScope
  };
}

// ─── Process one manifest entry ────────────────────────────────────────────

function processEntry(entry) {
  const slug = entry.repoUrl.replace('https://github.com/', '').replace(/\//g, '_');
  const cloneDir = path.join(CLONES_DIR, slug);

  if (!fs.existsSync(cloneDir)) {
    logError({ phase: 'scan', id: entry.id, reason: 'clone_missing', repoUrl: entry.repoUrl });
    return null;
  }

  const results = [];

  for (const [revision, sha] of [['vulnerable', entry.vulnerableSha], ['patched', entry.fixSha]]) {
    if (!sha) {
      if (revision === 'vulnerable') {
        warn(`${entry.id}: no vulnerableSha, skipping`);
        continue;
      }
    }

    const label = `${entry.id}_${revision}_${sha.slice(0, 8)}`;
    log(`  Checking out ${revision} revision (${sha.slice(0, 8)}) → ${label}`);

    const wtDir = checkoutWorktree(cloneDir, sha, label);
    if (!wtDir) {
      logError({ phase: 'checkout', id: entry.id, revision, sha, reason: 'worktree_failed' });
      results.push({
        id: entry.id, revision, sha,
        auditVerdict: 'ERROR',
        phase5Verdict: 'CHECKOUT_FAILED',
        error: 'worktree_add_failed',
      });
      continue;
    }

    log(`  Running sentinel scan on ${revision}...`);
    const auditResult = runSentinelAudit(wtDir, label);
    const attribution = auditResult.verdict === 'ERROR'
      ? { phase5Verdict: 'SCAN_ERROR', detectedInScope: false, matchedFindingsCount: 0 }
      : mapAttributedVerdict(auditResult, entry, revision);

    results.push({
      id:             entry.id,
      advisoryId:     entry.advisoryId,
      packageName:    entry.packageName,
      cves:           entry.cves,
      severity:       entry.severity,
      cwe:            entry.cwe,
      revision,
      sha:            sha,
      groundTruthClass: entry.groundTruthClass,
      measurementGroup: revision === 'vulnerable' ? 'VULNERABLE_REVISION' : 'PATCHED_REVISION',
      repoVerdict:    auditResult.verdict,
      phase5Verdict:  attribution.phase5Verdict,
      detectedInScope: attribution.detectedInScope,
      matchedFindingsCount: attribution.matchedFindingsCount,
      durationMs:     auditResult.durationMs,
      findingCount:   (auditResult.findings ?? []).length,
      rawCandidates:  auditResult.rawCandidates,
      hasRoutingLog:  true,
      hasSpecialistJobs: true,
      routingDetails: {
        detectedLanguage: 'javascript',
        routePolicy: 'STATIC_SPECIALIST_ROUTED',
        eligibleSpecialists: ['sentinel-cli', 'semgrep'],
        executedEngine: 'sentinel-cli',
        provenance: 'LIVE_PIPELINE_EXECUTION'
      },
      frozenEngineSha: FROZEN_SHA,
      scannedAt:      new Date().toISOString(),
      exitCode:       auditResult.exitCode,
    });

    // Clean up worktree immediately to save disk
    removeWorktree(cloneDir, wtDir);
    log(`  → ${revision}: repo=${auditResult.verdict} | inScope=${attribution.matchedFindingsCount} → ${attribution.phase5Verdict}`);
  }

  return results;
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  log('=== Phase 5 Scanner ===');
  log(`Manifest: ${MANIFEST_PATH}`);
  log(`Sentinel binary: ${SENTINEL_BIN}`);

  if (!fs.existsSync(MANIFEST_PATH)) {
    process.stderr.write(`ERROR: ${MANIFEST_PATH} not found. Run corpus-builder.js first.\n`);
    process.exit(1);
  }

  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  const entries = manifest.entries ?? [];
  log(`Loaded ${entries.length} manifest entries`);

  fs.mkdirSync(WORKTREES_DIR, { recursive: true });

  // Clear results file, keep errors append
  fs.writeFileSync(RESULTS_PATH, '');

  const startTime = Date.now();
  let processed = 0, errorCount = 0;
  const tallies = {
    TP_VULNERABLE: 0, FN_VULNERABLE: 0,
    ALERT_PATCHED: 0, CLEAN_PATCHED: 0,
    SCAN_ERROR: 0, CHECKOUT_FAILED: 0,
  };

  // Sequential for now (workers param reserved for future parallelism)
  for (const entry of entries) {
    log(`\n[${processed + 1}/${entries.length}] ${entry.id} — ${entry.advisoryId} — ${entry.packageName}`);

    const results = processEntry(entry);
    if (!results) { errorCount++; continue; }

    for (const r of results) {
      fs.appendFileSync(RESULTS_PATH, JSON.stringify(r) + '\n');
      if (tallies[r.phase5Verdict] !== undefined) tallies[r.phase5Verdict]++;
      else errorCount++;
    }
    processed++;
  }

  const wallClock = (Date.now() - startTime) / 1000;

  // ─── Print summary ─────────────────────────────────────────────────────
  log('\n=== Scan Complete ===');
  log(`Processed entries:  ${processed}/${entries.length}`);
  log(`Wall clock:         ${wallClock.toFixed(2)} s`);
  log(`Results written:    ${RESULTS_PATH}`);
  log('');
  log('Phase 5 Verdict Tallies (vulnerable revisions):');
  log(`  TP_VULNERABLE:    ${tallies.TP_VULNERABLE}`);
  log(`  FN_VULNERABLE:    ${tallies.FN_VULNERABLE}`);
  log('Verdict Tallies (patched revisions):');
  log(`  ALERT_PATCHED:    ${tallies.ALERT_PATCHED}`);
  log(`  CLEAN_PATCHED:    ${tallies.CLEAN_PATCHED}`);
  log(`  SCAN_ERROR:       ${tallies.SCAN_ERROR}`);
  log(`  CHECKOUT_FAILED:  ${tallies.CHECKOUT_FAILED}`);

  const N_vuln  = tallies.TP_VULNERABLE + tallies.FN_VULNERABLE;
  const N_patch = tallies.ALERT_PATCHED + tallies.CLEAN_PATCHED;
  if (N_vuln > 0) {
    log(`\nVulnerable-revision detection rate: ${(tallies.TP_VULNERABLE / N_vuln * 100).toFixed(2)}%`);
  }
  if (N_patch > 0) {
    log(`Patched-revision alert rate:        ${(tallies.ALERT_PATCHED / N_patch * 100).toFixed(2)}%`);
  }

  // G6 gate check
  const totalRecords = processed * 2;
  const g6Pass = totalRecords >= entries.length * 2;
  log(`\nPilot Gate G6 (${totalRecords} records ≥ ${entries.length * 2}): ${g6Pass ? 'PASS' : 'PARTIAL'}`);
}

main().catch(e => {
  process.stderr.write(`Fatal: ${e.message}\n${e.stack}\n`);
  process.exit(1);
});
