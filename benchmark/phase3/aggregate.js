'use strict';

/**
 * Phase 3 — Metrics Aggregator
 *
 * Reads PHASE3_RESULTS.jsonl and produces:
 *   PHASE3_METRICS.json     — machine-readable metrics
 *   PHASE3_ENVIRONMENT.json — host + freeze metadata
 *   PHASE3_SUMMARY.md       — paper-ready narrative summary
 *
 * Usage: node aggregate.js
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { PATHS, CANONICAL_FREEZE, WORKERS_COUNT } = require('./config');

function readJsonl(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8')
    .split('\n')
    .filter(l => l.trim())
    .map(l => {
      try { return JSON.parse(l); } catch { return null; }
    })
    .filter(Boolean);
}

function pct(num, den) {
  if (!den) return 0;
  return (num / den * 100);
}

function fmt(n, decimals = 2) {
  return Number(n).toFixed(decimals);
}

async function aggregate() {
  const results = readJsonl(PATHS.resultsFile);
  const errors = readJsonl(PATHS.errorsFile);

  console.log(`Loaded ${results.length} result records, ${errors.length} error records.`);

  const total = results.length;

  // Verdict distribution
  const verdicts = { BLOCK: 0, REVIEW: 0, PASS: 0, TIMEOUT: 0, ERROR: 0, NO_ARTIFACT: 0 };
  // Classification (recall perspective)
  const classifications = { TP: 0, PARTIAL: 0, FN: 0, ERROR: 0, NO_ARTIFACT: 0 };

  // Engine totals
  let totalCloudAlerts = 0;
  let totalCliAlerts = 0;
  let totalOracleAlerts = 0;
  let totalRawCandidates = 0;
  let totalAgenticEscalations = 0;
  let totalToolCalls = 0;
  let totalConfirmedFindings = 0;
  let totalEscalatedConfirmed = 0;
  let totalAmbiguousFindings = 0;

  // Performance
  let sumExtractMs = 0;
  let sumCloudMs = 0;
  let sumCliMs = 0;
  let sumOracleMs = 0;
  let sumHybridMs = 0;
  let sumTotalWallMs = 0;
  let perfCount = 0;

  // Severity distribution
  const severityTotals = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const r of results) {
    const v = r.verdict || 'ERROR';
    verdicts[v] = (verdicts[v] || 0) + 1;

    const c = r.classification || 'ERROR';
    classifications[c] = (classifications[c] || 0) + 1;

    totalCloudAlerts += r.engines?.cloud?.totalAlerts || 0;
    totalCliAlerts += r.engines?.cli?.totalAlerts || 0;
    totalOracleAlerts += r.engines?.oracle?.totalAlerts || 0;
    totalRawCandidates += r.signals?.rawCandidatesTotal || 0;

    const sc = r.signals?.candidateCounts || {};
    severityTotals.critical += sc.critical || 0;
    severityTotals.high += sc.high || 0;
    severityTotals.medium += sc.medium || 0;
    severityTotals.low += sc.low || 0;

    totalAgenticEscalations += r.hybrid?.escalationCount || 0;
    totalToolCalls += r.hybrid?.toolCalls || 0;
    totalConfirmedFindings += r.hybrid?.confirmedFindings || 0;
    totalEscalatedConfirmed += r.hybrid?.escalatedConfirmedFindings || 0;
    totalAmbiguousFindings += r.hybrid?.ambiguousFindings || 0;

    if (r.performance) {
      sumExtractMs += r.performance.extractMs || 0;
      sumCloudMs += r.performance.cloudMs || 0;
      sumCliMs += r.performance.cliMs || 0;
      sumOracleMs += r.performance.oracleMs || 0;
      sumHybridMs += r.performance.hybridMs || 0;
      sumTotalWallMs += r.performance.totalWallMs || 0;
      perfCount++;
    }
  }

  const tp = classifications.TP;
  const partial = classifications.PARTIAL;
  const fn = classifications.FN + (classifications.ERROR || 0) + (classifications.NO_ARTIFACT || 0);
  const effectiveN = tp + partial + fn; // packages where we have a verdict

  // Escalation metrics
  const escalationSelectivity = totalRawCandidates > 0
    ? pct(totalAgenticEscalations, totalRawCandidates)
    : 0;
  const escalationYield = totalAgenticEscalations > 0
    ? pct(totalEscalatedConfirmed, totalAgenticEscalations)
    : 0;
  const suppressionRate = totalRawCandidates > 0
    ? pct(totalRawCandidates - totalAgenticEscalations, totalRawCandidates)
    : 0;

  // Recall
  const recallBlock = pct(tp, total);            // strict: only BLOCK counts
  const recallDetected = pct(tp + partial, total); // loose: BLOCK + REVIEW

  const metrics = {
    schemaVersion: '3.0',
    generatedAt: new Date().toISOString(),
    freeze: CANONICAL_FREEZE,
    corpus: {
      source: 'NPMStudy zip_malware',
      groundTruth: 'ALL_MALICIOUS',
      totalTargets: total,
      workers: WORKERS_COUNT
    },
    verdicts: {
      BLOCK: verdicts.BLOCK,
      REVIEW: verdicts.REVIEW,
      PASS: verdicts.PASS,
      TIMEOUT: verdicts.TIMEOUT || 0,
      ERROR: verdicts.ERROR || 0,
      NO_ARTIFACT: verdicts.NO_ARTIFACT || 0
    },
    verdictRates: {
      blockPct: fmt(pct(verdicts.BLOCK, total)),
      reviewPct: fmt(pct(verdicts.REVIEW, total)),
      passPct: fmt(pct(verdicts.PASS, total)),
      timeoutPct: fmt(pct(verdicts.TIMEOUT || 0, total)),
      errorPct: fmt(pct(verdicts.ERROR || 0, total)),
      noArtifactPct: fmt(pct(verdicts.NO_ARTIFACT || 0, total))
    },
    recall: {
      strict: {
        label: 'BLOCK only (TP)',
        TP: tp,
        FN: total - tp,
        recallPct: fmt(recallBlock)
      },
      loose: {
        label: 'BLOCK + REVIEW (detected)',
        detected: tp + partial,
        missed: total - tp - partial,
        detectionRatePct: fmt(recallDetected)
      }
    },
    engines: {
      cloudAlerts: totalCloudAlerts,
      cliAlerts: totalCliAlerts,
      oracleAlerts: totalOracleAlerts,
      totalRawCandidates
    },
    severityDistribution: severityTotals,
    hybridTriage: {
      totalAgenticEscalations,
      totalToolCalls,
      totalConfirmedFindings,
      totalEscalatedConfirmed,
      totalAmbiguousFindings,
      escalationSelectivityPct: fmt(escalationSelectivity),
      escalationYieldPct: fmt(escalationYield),
      suppressionRatePct: fmt(suppressionRate),
      rawCandidatesSuppressed: totalRawCandidates - totalAgenticEscalations
    },
    performance: {
      count: perfCount,
      avgExtractMs: fmt(perfCount > 0 ? sumExtractMs / perfCount : 0),
      avgCloudMs: fmt(perfCount > 0 ? sumCloudMs / perfCount : 0),
      avgCliMs: fmt(perfCount > 0 ? sumCliMs / perfCount : 0),
      avgOracleMs: fmt(perfCount > 0 ? sumOracleMs / perfCount : 0),
      avgHybridMs: fmt(perfCount > 0 ? sumHybridMs / perfCount : 0),
      avgTotalWallMsPerPackage: fmt(perfCount > 0 ? sumTotalWallMs / perfCount : 0)
    },
    errors: {
      campaignErrors: errors.length,
      scanErrors: verdicts.ERROR || 0
    }
  };

  const env = {
    schemaVersion: '3.0',
    generatedAt: new Date().toISOString(),
    freeze: CANONICAL_FREEZE,
    host: {
      platform: os.platform(),
      arch: os.arch(),
      cpus: os.cpus().length,
      nodeVersion: process.version,
      totalMemoryMB: Math.round(os.totalmem() / 1024 / 1024)
    },
    workers: WORKERS_COUNT,
    paths: {
      malwareDir: PATHS.malwareDir,
      resultsFile: PATHS.resultsFile
    }
  };

  // ─── Summary MD ───────────────────────────────────────────────────────────────

  const summaryLines = [
    `# Sentinel Phase 3 — NPMStudy Malicious Corpus Campaign`,
    ``,
    `**Generated:** ${new Date().toISOString()}`,
    `**Ground Truth:** ALL packages are MALICIOUS (NPMStudy \`zip_malware\` corpus)`,
    `**Objective:** Recall / True-Positive measurement at scale`,
    ``,
    `---`,
    ``,
    `## Corpus`,
    ``,
    `| Parameter | Value |`,
    `|---|---|`,
    `| Source | NPMStudy zip_malware |`,
    `| Total Targets Scanned | ${total} |`,
    `| Ground Truth | MALICIOUS (all) |`,
    `| Concurrency | ${WORKERS_COUNT} workers |`,
    `| Engine Freeze | audit@${CANONICAL_FREEZE.auditVersion} / cli@${CANONICAL_FREEZE.cliSha.slice(0,7)} / oracle@${CANONICAL_FREEZE.oracleSha.slice(0,7)} / cloud@${CANONICAL_FREEZE.cloudDeploymentSha.slice(0,7)} |`,
    `| Model | ${CANONICAL_FREEZE.model} @ T=${CANONICAL_FREEZE.temperature} |`,
    ``,
    `---`,
    ``,
    `## Verdict Distribution`,
    ``,
    `| Verdict | N | % |`,
    `|---|---|---|`,
    `| BLOCK | ${verdicts.BLOCK} | ${fmt(pct(verdicts.BLOCK, total))}% |`,
    `| REVIEW | ${verdicts.REVIEW} | ${fmt(pct(verdicts.REVIEW, total))}% |`,
    `| PASS | ${verdicts.PASS} | ${fmt(pct(verdicts.PASS, total))}% |`,
    `| TIMEOUT | ${verdicts.TIMEOUT || 0} | ${fmt(pct(verdicts.TIMEOUT || 0, total))}% |`,
    `| ERROR / NO_ARTIFACT | ${(verdicts.ERROR || 0) + (verdicts.NO_ARTIFACT || 0)} | ${fmt(pct((verdicts.ERROR || 0) + (verdicts.NO_ARTIFACT || 0), total))}% |`,
    ``,
    `---`,
    ``,
    `## Recall Metrics`,
    ``,
    `| Metric | Value |`,
    `|---|---|`,
    `| **Strict Recall (BLOCK = TP)** | **${fmt(recallBlock)}%** (${tp}/${total}) |`,
    `| Detection Rate (BLOCK + REVIEW) | ${fmt(recallDetected)}% (${tp + partial}/${total}) |`,
    `| False Negatives (PASS) | ${verdicts.PASS} (${fmt(pct(verdicts.PASS, total))}%) |`,
    ``,
    `---`,
    ``,
    `## Engine Signals`,
    ``,
    `| Engine | Raw Alerts |`,
    `|---|---|`,
    `| Cloud | ${totalCloudAlerts} |`,
    `| CLI | ${totalCliAlerts} |`,
    `| Oracle | ${totalOracleAlerts} |`,
    `| **Total Raw Candidates** | **${totalRawCandidates}** |`,
    ``,
    `**Severity Distribution of Raw Candidates:**`,
    ``,
    `| Severity | Count |`,
    `|---|---|`,
    `| CRITICAL | ${severityTotals.critical} |`,
    `| HIGH | ${severityTotals.high} |`,
    `| MEDIUM | ${severityTotals.medium} |`,
    `| LOW | ${severityTotals.low} |`,
    ``,
    `---`,
    ``,
    `## Hybrid Triage Funnel`,
    ``,
    `| Stage | Count | Rate |`,
    `|---|---|---|`,
    `| Raw Candidates | ${totalRawCandidates} | 100% baseline |`,
    `| Agentic Escalations | ${totalAgenticEscalations} | ${fmt(escalationSelectivity)}% of raw candidates |`,
    `| Confirmed via Escalation | ${totalEscalatedConfirmed} | ${fmt(escalationYield)}% yield of escalations |`,
    `| Suppressed (not escalated) | ${totalRawCandidates - totalAgenticEscalations} | ${fmt(suppressionRate)}% |`,
    ``,
    `**Escalation Selectivity at scale: ${fmt(escalationSelectivity)}%** (raw candidates → agentic escalation)`,
    `**Escalation Yield at scale: ${fmt(escalationYield)}%** (escalations → confirmed findings)`,
    ``,
    `---`,
    ``,
    `## Performance`,
    ``,
    `| Metric | Value |`,
    `|---|---|`,
    `| Avg extraction time | ${fmt(perfCount > 0 ? sumExtractMs / perfCount : 0)} ms/pkg |`,
    `| Avg Cloud scan time | ${fmt(perfCount > 0 ? sumCloudMs / perfCount : 0)} ms/pkg |`,
    `| Avg CLI scan time | ${fmt(perfCount > 0 ? sumCliMs / perfCount : 0)} ms/pkg |`,
    `| Avg Oracle scan time | ${fmt(perfCount > 0 ? sumOracleMs / perfCount : 0)} ms/pkg |`,
    `| Avg hybrid triage time | ${fmt(perfCount > 0 ? sumHybridMs / perfCount : 0)} ms/pkg |`,
    `| Avg total wall time | ${fmt(perfCount > 0 ? sumTotalWallMs / perfCount : 0)} ms/pkg |`,
    ``,
    `---`,
    ``,
    `## Campaign Errors`,
    ``,
    `| Type | Count |`,
    `|---|---|`,
    `| Campaign errors (fatal per package) | ${errors.length} |`,
    `| Scan errors (caught) | ${verdicts.ERROR || 0} |`,
    `| No artifact | ${verdicts.NO_ARTIFACT || 0} |`,
    ``
  ];

  // Write outputs
  fs.writeFileSync(PATHS.metricsFile, JSON.stringify(metrics, null, 2));
  fs.writeFileSync(PATHS.envFile, JSON.stringify(env, null, 2));
  fs.writeFileSync(PATHS.summaryFile, summaryLines.join('\n'));

  console.log('\n=======================================================');
  console.log('PHASE 3 AGGREGATION COMPLETE');
  console.log(`  Metrics:     ${PATHS.metricsFile}`);
  console.log(`  Environment: ${PATHS.envFile}`);
  console.log(`  Summary:     ${PATHS.summaryFile}`);
  console.log(`\n  Strict Recall (BLOCK): ${fmt(recallBlock)}% (${tp}/${total})`);
  console.log(`  Detection Rate (BLOCK+REVIEW): ${fmt(recallDetected)}% (${tp + partial}/${total})`);
  console.log(`  Escalation Selectivity: ${fmt(escalationSelectivity)}%`);
  console.log(`  Escalation Yield: ${fmt(escalationYield)}%`);
  console.log('=======================================================\n');

  return metrics;
}

if (require.main === module) {
  aggregate().catch(err => {
    console.error('Aggregation failed:', err);
    process.exit(1);
  });
}

module.exports = { aggregate };
