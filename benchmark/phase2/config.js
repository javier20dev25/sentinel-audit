'use strict';

/**
 * Phase 2 — Real-World Corpus Benchmark Configuration
 * 
 * Enforces immutable engine freezes and canonical parameters.
 */

const path = require('path');

const CANONICAL_FREEZE = {
  ecosystemSha: 'fee04e16f428369ecfb421c82d6420f9d3b7801d',
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
  phase2Dir: path.resolve(__dirname),
  manifestFile: path.join(__dirname, 'PHASE2_MANIFEST.json'),
  resultsFile: path.join(__dirname, 'PHASE2_RESULTS.jsonl'),
  errorsFile: path.join(__dirname, 'PHASE2_ERRORS.jsonl'),
  metricsFile: path.join(__dirname, 'PHASE2_METRICS.json'),
  envFile: path.join(__dirname, 'PHASE2_ENVIRONMENT.json'),
  summaryFile: path.join(__dirname, 'PHASE2_SUMMARY.md'),
  benignDir: 'C:/Users/sleyt/benchmark-corpus/npm/work/benign',
  blindBenignDir: 'C:/Users/sleyt/benchmark-corpus/npm/work/blind-benign'
};

const WORKERS_COUNT = 8;
const MAX_FILES_PER_PACKAGE = 400;

module.exports = {
  CANONICAL_FREEZE,
  PATHS,
  WORKERS_COUNT,
  MAX_FILES_PER_PACKAGE
};
