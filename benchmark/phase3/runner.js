'use strict';

/**
 * Phase 3 — Campaign Runner
 *
 * Scans 4,302 NPMStudy malicious tarballs through the full Sentinel Audit
 * hybrid pipeline (Cloud + CLI + Oracle engines + deterministic triage).
 *
 * Key differences from Phase 2:
 *   - Extracts .tgz via 7-Zip before scanning (Phase 2 had pre-extracted dirs)
 *   - Ground truth = MALICIOUS for all targets → BLOCK = TP, REVIEW/PASS = FN
 *   - Checkpoint/resume support (incremental JSONL append)
 *   - Progress bar shows TP/FN rates in real time
 *   - Cleans up extracted dirs after each package to avoid disk fill
 *
 * Usage:
 *   node runner.js               # Full campaign (4,302 packages)
 *   node runner.js --limit 50    # Test run
 *   node runner.js --resume      # Resume from checkpoint (skip already-scanned)
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { execSync } = require('child_process');

const {
  CANONICAL_FREEZE,
  PATHS,
  WORKERS_COUNT,
  MAX_FILES_PER_PACKAGE,
  PACKAGE_TIMEOUT_MS
} = require('./config');

const { CentralRateLimiter } = require('../phase2/rate-limiter');
const { CentralResultWriter } = require('./writer');
const { runEngine, normalizeAlert } = require('C:/Users/sleyt/sentinel-cloud/docs/benchmarks/runner/engines.cjs');
const { isAmbiguousCandidate, runDeterministicTool } = require('C:/Users/sleyt/sentinel-audit/workflow/hybrid-triage');

const SEVENZIP = PATHS.sevenZip;
const TMP_BASE = PATHS.tmpDir;

// ─── Extraction ────────────────────────────────────────────────────────────────

function extractTgz(tgzPath, workerId) {
  const tmpSub = path.join(TMP_BASE, `w${workerId}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`);
  fs.mkdirSync(tmpSub, { recursive: true });
  try {
    // Step 1: extract .tgz → .tar
    execSync(`"${SEVENZIP}" x "${tgzPath}" -o"${tmpSub}" -y`, {
      stdio: 'ignore',
      timeout: 6000
    });
    // Step 2: extract .tar (if present)
    const tar = fs.readdirSync(tmpSub).find(f => f.endsWith('.tar'));
    if (tar) {
      execSync(`"${SEVENZIP}" x "${path.join(tmpSub, tar)}" -o"${tmpSub}" -y`, {
        stdio: 'ignore',
        timeout: 6000
      });
      try { fs.unlinkSync(path.join(tmpSub, tar)); } catch {}
    }
    // Step 3: find package root (has package.json)
    let pkgDir = null;
    (function findDir(dir, depth) {
      if (depth > 3 || pkgDir) return;
      try {
        for (const sub of fs.readdirSync(dir)) {
          const c = path.join(dir, sub);
          try { if (!fs.statSync(c).isDirectory()) continue; } catch { continue; }
          if (fs.existsSync(path.join(c, 'package.json'))) { pkgDir = c; return; }
          findDir(c, depth + 1);
        }
      } catch {}
    })(tmpSub, 0);

    return { tmpSub, pkgDir };
  } catch (err) {
    // clean up on failure
    try { fs.rmSync(tmpSub, { recursive: true, force: true }); } catch {}
    throw err;
  }
}

function cleanupTmp(tmpSub) {
  try { fs.rmSync(tmpSub, { recursive: true, force: true }); } catch {}
}

// ─── File Walker ───────────────────────────────────────────────────────────────

const JS_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.json']);
const IGNORE_DIRS = new Set(['node_modules', '.git', 'test', 'tests', '__tests__', 'spec', 'specs', 'coverage', 'docs', 'doc', 'example', 'examples', 'benchmark', 'benchmarks', 'fixture', 'fixtures']);

function walkFiles(dir, maxFiles) {
  const results = [];
  function recurse(d) {
    if (results.length >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (results.length >= maxFiles) break;
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!IGNORE_DIRS.has(e.name)) recurse(full);
      } else if (e.isFile()) {
        if (JS_EXTS.has(path.extname(e.name).toLowerCase())) {
          results.push(full);
        }
      }
    }
  }
  recurse(dir);
  return results;
}

// ─── Severity Helpers ──────────────────────────────────────────────────────────

function parseSeverityBand(s) {
  if (s == null) return 'LOW';
  if (typeof s === 'number') {
    if (s >= 9) return 'CRITICAL';
    if (s >= 7) return 'HIGH';
    if (s >= 4) return 'MEDIUM';
    return 'LOW';
  }
  const str = String(s).toUpperCase();
  if (str.includes('CRIT')) return 'CRITICAL';
  if (str.includes('HIGH')) return 'HIGH';
  if (str.includes('MED')) return 'MEDIUM';
  return 'LOW';
}

// ─── Per-Package Scan ──────────────────────────────────────────────────────────

async function analyzePackage(target, workerId) {
  const tStart = process.hrtime.bigint();
  let tmpSub = null;
  let pkgDir = null;

  // 1. Extract tgz
  try {
    const extracted = extractTgz(target.tgzPath, workerId);
    tmpSub = extracted.tmpSub;
    pkgDir = extracted.pkgDir;
  } catch (err) {
    return {
      target: { targetId: target.targetId, packageName: target.packageName, version: target.version, groundTruth: target.groundTruth },
      verdict: 'ERROR',
      groundTruth: 'MALICIOUS',
      classification: 'ERROR',
      error: `Extract failed: ${err.message.slice(0, 100)}`,
      freeze: CANONICAL_FREEZE,
      provenance: { tgzSha256: target.tgzSha256, scannedAt: new Date().toISOString(), workerId }
    };
  }

  if (!pkgDir) {
    cleanupTmp(tmpSub);
    return {
      target: { targetId: target.targetId, packageName: target.packageName, version: target.version, groundTruth: target.groundTruth },
      verdict: 'NO_ARTIFACT',
      groundTruth: 'MALICIOUS',
      classification: 'FN',
      error: 'No package.json found in tarball',
      freeze: CANONICAL_FREEZE,
      provenance: { tgzSha256: target.tgzSha256, scannedAt: new Date().toISOString(), workerId }
    };
  }

  const performance = { extractMs: 0, cloudMs: 0, cliMs: 0, oracleMs: 0, hybridMs: 0, totalWallMs: 0 };
  const tExtract = process.hrtime.bigint();
  performance.extractMs = Number(tExtract - tStart) / 1e6;

  // 2. Walk files
  const allFiles = walkFiles(pkgDir, MAX_FILES_PER_PACKAGE);
  const fileCount = allFiles.length;

  const engineResults = {
    cloud: { totalAlerts: 0, alerts: [] },
    cli: { totalAlerts: 0, alerts: [] },
    oracle: { totalAlerts: 0, alerts: [] }
  };

  const rawCandidates = [];
  const candidateCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  // 3. Run engines on each file
  for (const fullPath of allFiles) {
    const relFile = path.relative(pkgDir, fullPath);
    let content = '';
    try { content = fs.readFileSync(fullPath, 'utf8'); } catch { continue; }

    // Cloud
    const t0Cloud = process.hrtime.bigint();
    let rCloud = { alerts: [] };
    try { rCloud = await runEngine('cloud', path.basename(relFile), content); } catch {}
    performance.cloudMs += Number(process.hrtime.bigint() - t0Cloud) / 1e6;

    for (const a of rCloud.alerts || []) {
      const na = normalizeAlert('cloud', a);
      const band = parseSeverityBand(na.severity);
      engineResults.cloud.totalAlerts++;
      engineResults.cloud.alerts.push({ file: relFile, type: na.id, severity: band });
      rawCandidates.push({
        source: 'cloud',
        file: relFile,
        rule: na.id,
        severity: band,
        detail: a.description || a.message || ''
      });
    }

    // CLI
    const t0Cli = process.hrtime.bigint();
    let rCli = { alerts: [] };
    try { rCli = await runEngine('cli', path.basename(relFile), content); } catch {}
    performance.cliMs += Number(process.hrtime.bigint() - t0Cli) / 1e6;

    for (const a of rCli.alerts || []) {
      const na = normalizeAlert('cli', a);
      const band = parseSeverityBand(na.severity);
      engineResults.cli.totalAlerts++;
      engineResults.cli.alerts.push({ file: relFile, type: na.id, severity: band });
      rawCandidates.push({
        source: 'cli',
        file: relFile,
        rule: na.id,
        severity: band,
        detail: a.message || a.detail || ''
      });
    }

    // Oracle
    const t0Oracle = process.hrtime.bigint();
    let rOracle = { alerts: [] };
    try { rOracle = await runEngine('oracle', path.basename(relFile), content); } catch {}
    performance.oracleMs += Number(process.hrtime.bigint() - t0Oracle) / 1e6;

    for (const a of rOracle.alerts || []) {
      const na = normalizeAlert('oracle', a);
      const band = parseSeverityBand(na.severity);
      engineResults.oracle.totalAlerts++;
      engineResults.oracle.alerts.push({ file: relFile, type: na.id, severity: band });
      rawCandidates.push({
        source: 'oracle',
        file: relFile,
        rule: na.id,
        severity: band,
        detail: a.message || a.detail || a.title || ''
      });
    }
  }

  // Count candidate severities
  for (const c of rawCandidates) {
    if (c.severity === 'CRITICAL') candidateCounts.critical++;
    else if (c.severity === 'HIGH') candidateCounts.high++;
    else if (c.severity === 'MEDIUM') candidateCounts.medium++;
    else candidateCounts.low++;
  }

  // 4. Hybrid Triage
  const t0Hybrid = process.hrtime.bigint();
  let agenticEscalations = 0;
  let toolCalls = 0;
  let confirmedFindings = 0;
  let escalatedConfirmedFindings = 0;
  let deterministicConfirmedFindings = 0;
  let falsePositiveFindings = 0;
  let ambiguousFindings = 0;
  const toolResults = [];

  for (const cand of rawCandidates) {
    if (isAmbiguousCandidate(cand)) {
      agenticEscalations++;
      toolCalls++;
      const df = runDeterministicTool('inspect_dataflow', [cand.file], pkgDir);
      toolResults.push({ file: cand.file, tool: 'inspect_dataflow', outcome: df.slice(0, 150) });
      if (df.includes('EXPLOITABLE')) {
        confirmedFindings++;
        escalatedConfirmedFindings++;
      } else if (df.includes('BENIGN') || df.includes('CLEAN')) {
        falsePositiveFindings++;
      } else {
        ambiguousFindings++;
      }
    } else {
      if (cand.severity === 'CRITICAL') {
        confirmedFindings++;
        deterministicConfirmedFindings++;
      } else {
        falsePositiveFindings++;
      }
    }
  }
  performance.hybridMs = Number(process.hrtime.bigint() - t0Hybrid) / 1e6;

  // 5. Verdict
  let finalVerdict;
  if (candidateCounts.critical > 0 || confirmedFindings > 0) finalVerdict = 'BLOCK';
  else if (candidateCounts.high > 0 || candidateCounts.medium > 5 || ambiguousFindings > 0) finalVerdict = 'REVIEW';
  else finalVerdict = 'PASS';

  performance.totalWallMs = Number(process.hrtime.bigint() - tStart) / 1e6;

  // 6. Cleanup
  cleanupTmp(tmpSub);

  // 7. Classify (recall / TP measurement)
  // Ground truth = MALICIOUS → BLOCK = TP, REVIEW = partial/FN-soft, PASS = FN
  let classification;
  if (finalVerdict === 'BLOCK') classification = 'TP';
  else if (finalVerdict === 'REVIEW') classification = 'PARTIAL';  // detected but not blocked
  else if (finalVerdict === 'PASS') classification = 'FN';
  else classification = 'NO_ARTIFACT';

  return {
    target: {
      targetId: target.targetId,
      packageName: target.packageName,
      version: target.version,
      groundTruth: target.groundTruth,
      tgzSizeBytes: target.tgzSizeBytes,
      fileCount
    },
    verdict: finalVerdict,
    groundTruth: 'MALICIOUS',
    classification,
    freeze: CANONICAL_FREEZE,
    engines: {
      cloud: { totalAlerts: engineResults.cloud.totalAlerts },
      cli: { totalAlerts: engineResults.cli.totalAlerts },
      oracle: { totalAlerts: engineResults.oracle.totalAlerts }
    },
    signals: {
      rawCandidatesTotal: rawCandidates.length,
      candidateCounts
    },
    hybrid: {
      agenticEscalated: agenticEscalations > 0,
      escalationCount: agenticEscalations,
      toolCalls,
      confirmedFindings,
      escalatedConfirmedFindings,
      deterministicConfirmedFindings,
      falsePositiveFindings,
      ambiguousFindings,
      finalVerdict
    },
    performance,
    provenance: {
      tgzSha256: target.tgzSha256,
      scannedAt: new Date().toISOString(),
      workerId
    }
  };
}

// ─── Checkpoint Support ────────────────────────────────────────────────────────

function loadCheckpoint() {
  try {
    if (!fs.existsSync(PATHS.checkpointFile)) return new Set();
    const data = JSON.parse(fs.readFileSync(PATHS.checkpointFile, 'utf8'));
    return new Set(data.completed || []);
  } catch {
    return new Set();
  }
}

function saveCheckpoint(completedSet) {
  try {
    fs.writeFileSync(PATHS.checkpointFile, JSON.stringify({ completed: [...completedSet], savedAt: new Date().toISOString() }, null, 2));
  } catch {}
}

// ─── Campaign Controller ───────────────────────────────────────────────────────

async function runCampaign(options = {}) {
  const manifestData = JSON.parse(fs.readFileSync(PATHS.manifestFile, 'utf8'));
  const allTargets = manifestData.targets || [];
  const limit = options.limit || allTargets.length;
  const resume = !!options.resume;

  // Ensure tmp dir exists
  fs.mkdirSync(TMP_BASE, { recursive: true });

  // Checkpoint resume
  const completed = resume ? loadCheckpoint() : new Set();
  let targets = allTargets.slice(0, limit);
  if (resume && completed.size > 0) {
    const before = targets.length;
    targets = targets.filter(t => !completed.has(t.targetId));
    console.log(`[RESUME] Skipping ${before - targets.length} already-completed targets. Remaining: ${targets.length}`);
  }

  console.log('═'.repeat(70));
  console.log('  SENTINEL PHASE 3 — NPMStudy MALICIOUS CORPUS CAMPAIGN');
  console.log(`  Targets: ${targets.length} | Workers: ${WORKERS_COUNT} | Ground Truth: ALL MALICIOUS`);
  console.log(`  Model: ${CANONICAL_FREEZE.model} | Audit: ${CANONICAL_FREEZE.auditVersion}`);
  console.log(`  Timeout per package: ${PACKAGE_TIMEOUT_MS}ms`);
  console.log('═'.repeat(70) + '\n');

  // Writer: append mode for resume support
  const writer = new CentralResultWriter({ overwrite: !resume });
  const limiter = new CentralRateLimiter({ maxConcurrent: WORKERS_COUNT });

  let done = 0;
  let tp = 0, partial = 0, fn = 0, errors = 0, noArtifact = 0;
  const tStartCampaign = Date.now();

  const workerPromises = targets.map(async (target, idx) => {
    await limiter.acquire();
    const workerId = (idx % WORKERS_COUNT) + 1;
    try {
      const timeoutPromise = new Promise(resolve =>
        setTimeout(() => resolve({
          target: { targetId: target.targetId, packageName: target.packageName, version: target.version, groundTruth: target.groundTruth },
          verdict: 'TIMEOUT',
          groundTruth: 'MALICIOUS',
          classification: 'FN',
          error: 'Package scan timed out',
          freeze: CANONICAL_FREEZE,
          provenance: { tgzSha256: target.tgzSha256, scannedAt: new Date().toISOString(), workerId }
        }), PACKAGE_TIMEOUT_MS)
      );

      const result = await Promise.race([analyzePackage(target, workerId), timeoutPromise]);
      writer.writeResult(result);
      completed.add(target.targetId);

      // Track metrics
      if (result.classification === 'TP') tp++;
      else if (result.classification === 'PARTIAL') partial++;
      else if (result.classification === 'FN') fn++;
      else if (result.classification === 'ERROR') errors++;
      else noArtifact++;

      done++;

      // Progress: every 25 or at the end
      if (done % 25 === 0 || done === targets.length) {
        const elapsed = ((Date.now() - tStartCampaign) / 1000).toFixed(1);
        const rate = done / ((Date.now() - tStartCampaign) / 1000);
        const eta = ((targets.length - done) / rate).toFixed(0);
        const recall = done > 0 ? ((tp / done) * 100).toFixed(1) : '0.0';
        console.log(
          `[${new Date().toISOString().slice(11, 19)}] ${done}/${targets.length} | ` +
          `TP=${tp} PARTIAL=${partial} FN=${fn} ERR=${errors} | ` +
          `Recall=${recall}% | ${elapsed}s elapsed | ETA ~${eta}s`
        );
        // Save checkpoint every 100
        if (done % 100 === 0) saveCheckpoint(completed);
      }
    } catch (err) {
      writer.writeError({
        targetId: target.targetId,
        workerId,
        error: err.message,
        stack: err.stack?.slice(0, 300),
        timestamp: new Date().toISOString()
      });
      errors++;
      done++;
      console.error(`[ERR] ${target.targetId}: ${err.message.slice(0, 80)}`);
    } finally {
      limiter.release();
    }
  });

  await Promise.all(workerPromises);
  const writeStats = await writer.close();
  saveCheckpoint(completed);

  const totalWallMs = Date.now() - tStartCampaign;

  console.log('\n' + '═'.repeat(70));
  console.log('  PHASE 3 CAMPAIGN COMPLETE');
  console.log(`  Written: ${writeStats.totalWritten} | Errors: ${writeStats.totalErrors}`);
  console.log(`  TP: ${tp} | PARTIAL: ${partial} | FN: ${fn} | ERRORS: ${errors} | NO_ARTIFACT: ${noArtifact}`);
  console.log(`  Recall (BLOCK): ${targets.length > 0 ? ((tp / targets.length) * 100).toFixed(2) : 0}%`);
  console.log(`  Partial detection: ${targets.length > 0 ? ((partial / targets.length) * 100).toFixed(2) : 0}%`);
  console.log(`  Wall time: ${(totalWallMs / 1000).toFixed(2)}s`);
  console.log('═'.repeat(70));

  return { writeStats, totalWallMs, tp, partial, fn, errors, noArtifact, total: targets.length };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const limitIdx = args.indexOf('--limit');
  const limit = limitIdx !== -1 ? parseInt(args[limitIdx + 1], 10) : null;
  const resume = args.includes('--resume');
  runCampaign({ limit, resume }).catch(err => {
    console.error('Fatal campaign error:', err);
    process.exit(1);
  });
}

module.exports = { runCampaign, analyzePackage };
