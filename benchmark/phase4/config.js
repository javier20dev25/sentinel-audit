/**
 * Phase 4 — OWASP Benchmark Java v1.2 Configuration
 * Language-Aware Routing Experiment (AI DISABLED)
 *
 * FROZEN: Do not modify specialist versions during campaign.
 */
'use strict';

const path = require('path');

// ── Corpus ──────────────────────────────────────────────────────────────────
const CORPUS_ROOT   = path.resolve('C:/Users/sleyt/benchmark-corpus/owasp');
const TESTCODE_DIR  = path.join(CORPUS_ROOT, 'src/main/java/org/owasp/benchmark/testcode');
const EXPECTED_CSV  = path.join(CORPUS_ROOT, 'expectedresults-1.2.csv');

// ── Phase 4 output directory ─────────────────────────────────────────────────
const PHASE4_DIR    = path.resolve(__dirname);

// ── Experiment parameters ────────────────────────────────────────────────────
const WORKERS       = 8;
const TIMEOUT_MS    = 120_000;  // per-file semgrep timeout (120s: first run downloads p/java rules ~70s)

// ── AI / LLM ─────────────────────────────────────────────────────────────────
// MUST remain false for Phase 4: we isolate language-aware routing only.
const AI_ENABLED    = false;

// ── Semgrep config ───────────────────────────────────────────────────────────
// p/java pulls OWASP / Java rules from the Semgrep registry.
// The standalone runner bypasses sentinel-audit's allowRemoteRules=false policy.
const SEMGREP_CONFIG = 'p/java';

// ── Environment freeze (recorded in PHASE4_ENVIRONMENT.json) ─────────────────
const ENVIRONMENT = {
  auditVersion:          '1.1.0',
  auditSha:              'd70c6ea8899438b67494d41570084884fe7fbc96',
  cliSha:                'ae10c223',
  oracleSha:             '292123e1',
  cloudClientSha:        '924d25d2',
  cloudDeploymentSha:    'ebc469a',
  semgrepVersion:        '1.175.0',
  semgrepConfig:         SEMGREP_CONFIG,
  codeqlVersion:         'NOT_INSTALLED',
  model:                 'DISABLED',
  aiEnabled:             false,
  workers:               WORKERS,
  timeoutMs:             TIMEOUT_MS,
  phase:                 4,
  corpus:                'OWASP Benchmark Java v1.2',
  corpusN:               2740,
  groundTruth:           EXPECTED_CSV,
  buildMode:             'none',  // CodeQL flag (N/A — CodeQL not installed)
  note:                  'Standalone runner; does NOT invoke sentinel-audit audit pipeline or Sentinel Cloud.',
};

// ── OWASP category → CWE mapping (from expectedresults-1.2.csv) ──────────────
const CATEGORY_CWE = {
  pathtraver:   22,
  hash:         328,
  crypto:       327,
  cmdi:         78,
  sqli:         89,
  weakrand:     330,
  xpath:        643,
  trustbound:   501,
  ldapi:        90,
  xss:          80,
  securecookie: 614,
};

// ── Verdict labels ────────────────────────────────────────────────────────────
const VERDICT = {
  TRUE_POSITIVE:    'TRUE_POSITIVE',
  TRUE_NEGATIVE:    'TRUE_NEGATIVE',
  FALSE_POSITIVE:   'FALSE_POSITIVE',
  FALSE_NEGATIVE:   'FALSE_NEGATIVE',
  UNSCANNABLE:      'UNSCANNABLE',
  ROUTING_ERROR:    'ROUTING_ERROR',
  SPECIALIST_ERROR: 'SPECIALIST_ERROR',
  TIMEOUT:          'TIMEOUT',
};

module.exports = {
  CORPUS_ROOT,
  TESTCODE_DIR,
  EXPECTED_CSV,
  PHASE4_DIR,
  WORKERS,
  TIMEOUT_MS,
  AI_ENABLED,
  SEMGREP_CONFIG,
  ENVIRONMENT,
  CATEGORY_CWE,
  VERDICT,
};
