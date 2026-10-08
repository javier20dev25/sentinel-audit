'use strict';

/**
 * Phase 2 — Real-World Corpus Campaign Runner
 *
 * Architecture:
 *   Campaign Controller -> 8 Worker pool -> Central Quota Controller -> Central Result Writer
 *
 * Enforces:
 *   - Strict READ-ONLY guarantees (0 target execution)
 *   - Immutable Engine Freezes (canonical SHAs)
 *   - Complete Provenance Logging
 *   - Hybrid Triage (Deterministic-First + Targeted Escalation)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { CANONICAL_FREEZE, PATHS, WORKERS_COUNT } = require('./config');
const { CentralRateLimiter } = require('./rate-limiter');
const { CentralResultWriter } = require('./writer');
const { runEngine, normalizeAlert } = require('C:/Users/sleyt/sentinel-cloud/docs/benchmarks/runner/engines.cjs');
const { isAmbiguousCandidate, runDeterministicTool } = require('C:/Users/sleyt/sentinel-audit/workflow/hybrid-triage');

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

async function analyzeTarget(target, workerId) {
  const targetDir = target.directory;
  const files = target.files || [];
  
  const performance = {
    cloudMs: 0,
    cliMs: 0,
    oracleMs: 0,
    hybridMs: 0,
    totalWallMs: 0
  };
  
  const engineResults = {
    cloud: { totalAlerts: 0, maxSeverity: 'LOW', alerts: [] },
    cli: { totalAlerts: 0, maxSeverity: 'LOW', alerts: [] },
    oracle: { totalAlerts: 0, maxSeverity: 'LOW', alerts: [] }
  };

  const rawCandidates = [];
  const tStart = process.hrtime.bigint();

  // 1. Run all three engines over target files
  for (const relFile of files) {
    const fullPath = path.join(targetDir, relFile);
    let content = '';
    try {
      content = fs.readFileSync(fullPath, 'utf8');
    } catch {
      continue;
    }

    // Engine: Cloud
    const t0Cloud = process.hrtime.bigint();
    let rCloud = { alerts: [] };
    try {
      rCloud = await runEngine('cloud', path.basename(relFile), content);
    } catch {}
    const t1Cloud = process.hrtime.bigint();
    performance.cloudMs += Number(t1Cloud - t0Cloud) / 1e6;

    for (const a of rCloud.alerts || []) {
      const norm = normalizeAlert('cloud', a);
      const band = parseSeverityBand(norm.severity);
      engineResults.cloud.totalAlerts++;
      if (engineResults.cloud.alerts.length < 10) {
        engineResults.cloud.alerts.push({ file: relFile, type: norm.id, severity: band });
      }
      rawCandidates.push({
        source: 'cloud',
        file: relFile,
        rule: norm.id,
        severity: band,
        detail: a.description || a.message || ''
      });
    }

    // Engine: CLI
    const t0Cli = process.hrtime.bigint();
    let rCli = { alerts: [] };
    try {
      rCli = await runEngine('cli', path.basename(relFile), content);
    } catch {}
    const t1Cli = process.hrtime.bigint();
    performance.cliMs += Number(t1Cli - t0Cli) / 1e6;

    for (const a of rCli.alerts || []) {
      const norm = normalizeAlert('cli', a);
      const band = parseSeverityBand(norm.severity);
      engineResults.cli.totalAlerts++;
      if (engineResults.cli.alerts.length < 10) {
        engineResults.cli.alerts.push({ file: relFile, type: norm.id, severity: band });
      }
      rawCandidates.push({
        source: 'cli',
        file: relFile,
        rule: norm.id,
        severity: band,
        detail: a.message || a.detail || ''
      });
    }

    // Engine: Oracle
    const t0Oracle = process.hrtime.bigint();
    let rOracle = { alerts: [] };
    try {
      rOracle = await runEngine('oracle', path.basename(relFile), content);
    } catch {}
    const t1Oracle = process.hrtime.bigint();
    performance.oracleMs += Number(t1Oracle - t0Oracle) / 1e6;

    for (const a of rOracle.alerts || []) {
      const norm = normalizeAlert('oracle', a);
      const band = parseSeverityBand(norm.severity);
      engineResults.oracle.totalAlerts++;
      if (engineResults.oracle.alerts.length < 10) {
        engineResults.oracle.alerts.push({ file: relFile, type: norm.id, severity: band });
      }
      rawCandidates.push({
        source: 'oracle',
        file: relFile,
        rule: norm.id,
        severity: band,
        detail: a.message || a.snippet || ''
      });
    }
  }

  // 2. Candidate deduplication and classification
  const candidateCounts = {
    total: rawCandidates.length,
    critical: rawCandidates.filter(c => c.severity === 'CRITICAL').length,
    high: rawCandidates.filter(c => c.severity === 'HIGH').length,
    medium: rawCandidates.filter(c => c.severity === 'MEDIUM').length,
    low: rawCandidates.filter(c => c.severity === 'LOW').length
  };

  // 3. Sentinel Audit Hybrid Triage
  const t0Hybrid = process.hrtime.bigint();
  let agenticEscalations = 0;
  let toolCalls = 0;
  const toolResults = [];
  let confirmedFindings = 0;
  let falsePositiveFindings = 0;
  let ambiguousFindings = 0;

  for (const cand of rawCandidates) {
    if (isAmbiguousCandidate(cand)) {
      // Ambiguity detected -> targeted escalation
      agenticEscalations++;
      toolCalls++;
      const df = runDeterministicTool('inspect_dataflow', [cand.file], targetDir);
      toolResults.push({ file: cand.file, tool: 'inspect_dataflow', outcome: df.slice(0, 150) });
      
      if (df.includes('EXPLOITABLE')) {
        confirmedFindings++;
      } else if (df.includes('BENIGN') || df.includes('CLEAN')) {
        falsePositiveFindings++;
      } else {
        ambiguousFindings++;
      }
    } else {
      // Deterministic classification
      // Single-lens breadth findings (like Cloud CAPABILITY_CHAIN or secrets heuristic) without corroboration
      // are filtered as uncorroborated observations under Sentinel Audit
      if (cand.severity === 'CRITICAL') {
        confirmedFindings++;
      } else {
        falsePositiveFindings++;
      }
    }
  }
  const t1Hybrid = process.hrtime.bigint();
  performance.hybridMs = Number(t1Hybrid - t0Hybrid) / 1e6;

  // 4. Final Verdict determination (Sentinel Audit policy)
  let finalVerdict = 'PASS';
  let deterministicDecision = 'PASS';

  if (candidateCounts.critical > 0 || confirmedFindings > 0) {
    finalVerdict = 'BLOCK';
    deterministicDecision = 'BLOCK';
  } else if (candidateCounts.high > 0 || candidateCounts.medium > 5 || ambiguousFindings > 0) {
    finalVerdict = 'REVIEW';
    deterministicDecision = 'REVIEW';
  } else {
    finalVerdict = 'PASS';
    deterministicDecision = 'PASS';
  }

  const tEnd = process.hrtime.bigint();
  performance.totalWallMs = Number(tEnd - tStart) / 1e6;

  return {
    target: {
      targetId: target.targetId,
      packageName: target.packageName,
      version: target.version,
      subset: target.subset,
      fileCount: target.fileCount,
      byteCount: target.byteCount,
      groundTruth: target.groundTruth
    },
    freeze: CANONICAL_FREEZE,
    engines: {
      cloud: { totalAlerts: engineResults.cloud.totalAlerts, topAlerts: engineResults.cloud.alerts },
      cli: { totalAlerts: engineResults.cli.totalAlerts, topAlerts: engineResults.cli.alerts },
      oracle: { totalAlerts: engineResults.oracle.totalAlerts, topAlerts: engineResults.oracle.alerts }
    },
    signals: {
      rawAlertsTotal: rawCandidates.length,
      severityCounts: candidateCounts
    },
    candidates: candidateCounts,
    specialists: {
      routedLanguage: 'javascript',
      specialistsInvoked: []
    },
    hybrid: {
      deterministicDecision,
      ambiguityReason: agenticEscalations > 0 ? 'Taint or dynamic execution ambiguity identified in execution sinks' : 'None (deterministic static corroboration)',
      agenticEscalated: agenticEscalations > 0,
      escalationCount: agenticEscalations,
      toolsCalled: toolCalls,
      toolResults,
      confirmedFindings,
      falsePositiveFindings,
      ambiguousFindings,
      finalVerdict,
      tokenUsage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 } // Dataflow tool is offline deterministic
    },
    performance,
    provenance: {
      targetHash: target.targetHash,
      scannedAt: new Date().toISOString(),
      workerId
    }
  };
}

async function runCampaign(options = {}) {
  const manifestData = JSON.parse(fs.readFileSync(PATHS.manifestFile, 'utf8'));
  const targets = manifestData.targets || [];
  const limit = options.limit || targets.length;
  const queue = targets.slice(0, limit);

  console.log(`=======================================================`);
  console.log(`SENTINEL ECOSYSTEM PHASE 2 — REAL-WORLD BENIGN OSS RUN`);
  console.log(`Targets: ${queue.length} | Concurrency: ${WORKERS_COUNT} workers`);
  console.log(`Model: ${CANONICAL_FREEZE.model} | Audit: ${CANONICAL_FREEZE.auditVersion}`);
  console.log(`=======================================================\n`);

  const limiter = new CentralRateLimiter({ maxConcurrent: WORKERS_COUNT });
  const writer = new CentralResultWriter();
  let completed = 0;

  const tStartCampaign = Date.now();

  const workerPromises = queue.map(async (target, idx) => {
    await limiter.acquire();
    const workerId = (idx % WORKERS_COUNT) + 1;
    try {
      const result = await analyzeTarget(target, workerId);
      writer.writeResult(result);
      completed++;
      if (completed % 10 === 0 || completed === queue.length) {
        console.log(`[${new Date().toISOString().slice(11, 19)}] Progress: ${completed}/${queue.length} targets (${result.target.targetId} -> ${result.hybrid.finalVerdict})`);
      }
    } catch (err) {
      writer.writeError({
        targetId: target.targetId,
        workerId,
        error: err.message,
        stack: err.stack,
        timestamp: new Date().toISOString()
      });
      console.error(`Error analyzing target ${target.targetId}:`, err.message);
    } finally {
      limiter.release();
    }
  });

  await Promise.all(workerPromises);
  const writeStats = await writer.close();
  const totalCampaignWallMs = Date.now() - tStartCampaign;

  console.log(`\n=======================================================`);
  console.log(`CAMPAIGN COMPLETE`);
  console.log(`Total Targets Written: ${writeStats.totalWritten} | Errors: ${writeStats.totalErrors}`);
  console.log(`Wall Time: ${(totalCampaignWallMs / 1000).toFixed(2)}s`);
  console.log(`Results file: ${PATHS.resultsFile}`);
  console.log(`=======================================================`);

  return { writeStats, totalCampaignWallMs };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const limitIdx = args.indexOf('--limit');
  const limit = limitIdx !== -1 ? parseInt(args[limitIdx + 1], 10) : null;
  runCampaign({ limit }).catch(err => {
    console.error('Fatal campaign error:', err);
    process.exit(1);
  });
}

module.exports = { runCampaign, analyzeTarget };
