'use strict';

/**
 * Phase 3 — NPMStudy Expanded Malicious Corpus Configuration
 *
 * Ground truth: ALL packages are MALICIOUS (NPMStudy zip_malware corpus).
 * This is a RECALL / TP measurement run.
 *
 * Engines FROZEN — do NOT modify sentinel-cli, sentinel-oracle,
 * sentinel-cloud, or sentinel-audit during the campaign.
 */

const path = require('path');

const CANONICAL_FREEZE = {
  ecosystemSha: 'eb4ac1c',
  auditVersion: '1.1.0',
  auditSha: '012e095bc362129253435328e246c4f901e7842d',
  cliSha: 'ae10c223db766a041cb8a3dda561485769b47877',
  oracleSha: '292123e1e2be22781c0184eb444c1b6be9f1840a',
  cloudClientSha: '924d25d2362545fb58a39189d941f64404614093',
  cloudDeploymentSha: 'ebc469ae9797f269f4cc20c1b322260e97bc0b7a',
  model: 'google/gemini-3.5-flash-lite',
  temperature: 0.0
};

const PATHS = {
  phase3Dir: path.resolve(__dirname),
  manifestFile: path.join(__dirname, 'PHASE3_MANIFEST.json'),
  resultsFile: path.join(__dirname, 'PHASE3_RESULTS.jsonl'),
  errorsFile: path.join(__dirname, 'PHASE3_ERRORS.jsonl'),
  metricsFile: path.join(__dirname, 'PHASE3_METRICS.json'),
  envFile: path.join(__dirname, 'PHASE3_ENVIRONMENT.json'),
  summaryFile: path.join(__dirname, 'PHASE3_SUMMARY.md'),
  checkpointFile: path.join(__dirname, 'PHASE3_CHECKPOINT.json'),
  malwareDir: 'C:/Users/sleyt/sentinel-cloud/.c7-sandbox/scratch/benchmark/raw/NPMStudy-full/NPMStudy/Dataset/zip_malware',
  tmpDir: path.join(__dirname, 'tmp-extract'),
  sevenZip: 'C:\\Program Files\\7-Zip\\7z.exe'
};

const WORKERS_COUNT = 8;
const MAX_FILES_PER_PACKAGE = 400;
const PACKAGE_TIMEOUT_MS = 12000; // tgz extraction + scan; more generous than Phase 2 (no extraction there)

module.exports = {
  CANONICAL_FREEZE,
  PATHS,
  WORKERS_COUNT,
  MAX_FILES_PER_PACKAGE,
  PACKAGE_TIMEOUT_MS
};
