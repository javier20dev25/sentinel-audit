'use strict';
/**
 * Sentinel AI Benchmark — Case Manifest
 *
 * Defines the 28 evaluation units (26 cases + 2 semantic pair variants)
 * with their input payload per mode. Ground truth lives in ground-truth.js.
 *
 * Rules:
 *  - AI receives ONLY the fields marked for its mode.
 *  - "groundTruth" field is NEVER included in AI prompts.
 *  - Sentinel findings/expediente are NEVER shown in AI_ALONE mode.
 */

const fs = require('fs');
const path = require('path');
const TEMP = process.env.TEMP;

function readBenchFileJson(name) {
  const fpath = path.join(TEMP, name);
  if (!fs.existsSync(fpath)) return null;
  let raw;
  try { raw = fs.readFileSync(fpath, 'utf16le'); } catch (_) { raw = fs.readFileSync(fpath, 'utf8'); }
  const idx = raw.search(/\{\s*"host":/);
  if (idx !== -1) raw = raw.slice(idx);
  try { return JSON.parse(raw); } catch (_) { return null; }
}

function readBenignCase(caseId) {
  const dir = path.join(TEMP, 'sentinel_benign_corpus', caseId);
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, '_manifest.json'), 'utf8'));
  return manifest;
}

function readFile(fpath) {
  try { return fs.readFileSync(fpath, 'utf8'); } catch (_) { return null; }
}

// ----- Malicious case inputs -----
const pr12Path = path.join(TEMP, 'merx_pr12');
const healthCheck = readFile(path.join(pr12Path, 'scripts', 'health-check.js'));
const reportUtils = readFile(path.join(pr12Path, 'scripts', 'report-utils.js'));
const packageJson = readFile(path.join(pr12Path, 'package.json'));
const serverJs    = readFile(path.join(pr12Path, 'server.js'));
const fundamentalTxt = readFile(path.join(pr12Path, 'fundamental.txt'));

// Cloud signals (normalized subset for SENTINEL_ASSISTED)
const cliLocal = readBenchFileJson('bench_w1_cli_local.json');
const cloudHosted = readBenchFileJson('bench_w2_cli_cloud.json');

// PR diff summary for context
const PR12_DIFF_SUMMARY = `
Commit: b70c277 (over base 201a949)
PR #12 — 3 files changed:
  + scripts/health-check.js  (new file, 36 lines)
  + scripts/report-utils.js  (new file, 18 lines)
  M package.json             (scripts section modified: added prestart, postinstall hooks)
`.trim();

// ----- Sentinel Assisted context for malicious cases -----
const SENTINEL_ASSISTED_CONTEXT_MALICIOUS = {
  source: 'Sentinel Audit Expediente + Cloud Scan',
  cliFindings: (cliLocal && cliLocal.findings ? cliLocal.findings : [])
    .filter(f => ['NETWORK_ACTIVITY','UNSAFE_EVAL','COMMAND_INJECTION',
                  'ENV_ACCESS','LIFECYCLE_HOOK','OBFUSCATED_CODE'].includes(f.type))
    .map(f => ({ type: f.type, file: f.file, line: f.line, severity: f.severity, title: f.title, snippet: f.snippet })),
  cloudFindings: (cloudHosted && cloudHosted.findings ? cloudHosted.findings : [])
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH' || (f.riskScore && f.riskScore >= 6))
    .slice(0, 12)
    .map(f => ({ type: f.type, file: f.file, line: f.line, severity: f.severity, title: f.title,
                 snippet: f.snippet, riskScore: f.riskScore })),
  cloudMeta: {
    totalSignals: 64,
    actionableSignals: 8,
    observationOnly: 56,
    routingDecision: 'AMPLIFY',
    promotedFiles: ['scripts/health-check.js', 'scripts/report-utils.js', 'fundamental.txt', 'server.js'],
    routedSpecialists: ['codeql', 'semgrep'],
  },
};

// ----- Case definitions -----
const CASES = [
  // --- MALICIOUS ---
  {
    caseId: 'M01',
    groundTruth: 'MALICIOUS',
    AI_ALONE: {
      task: 'security-review',
      context: 'PR #12 diff — new file scripts/health-check.js',
      diff: PR12_DIFF_SUMMARY,
      code: { 'scripts/health-check.js': healthCheck },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Resolve the following Sentinel candidate for scripts/health-check.js',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      code: { 'scripts/health-check.js': healthCheck },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel Audit expediente for PR #12. Focus on scripts/health-check.js.',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      availableTools: ['inspect_source','inspect_dataflow','run_semgrep','search_history'],
      code: { 'scripts/health-check.js': healthCheck },
    },
  },
  {
    caseId: 'M02',
    groundTruth: 'MALICIOUS',
    AI_ALONE: {
      task: 'security-review',
      context: 'PR #12 diff — new file scripts/health-check.js (staging vector)',
      diff: PR12_DIFF_SUMMARY,
      code: { 'scripts/health-check.js': healthCheck },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Resolve the REMOTE_CODE_EXECUTION staged payload in scripts/health-check.js',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      code: { 'scripts/health-check.js': healthCheck },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel expediente PR #12. Focus on payload staging in scripts/health-check.js.',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      availableTools: ['inspect_source','inspect_dataflow','run_codeql','inspect_dependencies'],
      code: { 'scripts/health-check.js': healthCheck },
    },
  },
  {
    caseId: 'M03',
    groundTruth: 'MALICIOUS',
    AI_ALONE: {
      task: 'security-review',
      context: 'PR #12 — eval of remote content in health-check.js',
      diff: PR12_DIFF_SUMMARY,
      code: { 'scripts/health-check.js': healthCheck },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Resolve eval(stdout) candidate in scripts/health-check.js',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      code: { 'scripts/health-check.js': healthCheck },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel expediente PR #12. Focus on eval(stdout) in scripts/health-check.js.',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      availableTools: ['inspect_source','inspect_dataflow','run_semgrep'],
      code: { 'scripts/health-check.js': healthCheck },
    },
  },
  {
    caseId: 'M04',
    groundTruth: 'MALICIOUS',
    AI_ALONE: {
      task: 'security-review',
      context: 'PR #12 — new file scripts/report-utils.js',
      diff: PR12_DIFF_SUMMARY,
      code: { 'scripts/report-utils.js': reportUtils },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Resolve credential harvesting + exfil candidates in scripts/report-utils.js',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      code: { 'scripts/report-utils.js': reportUtils },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel expediente PR #12. Focus on scripts/report-utils.js data collection + exfil.',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      availableTools: ['inspect_source','run_codeql','inspect_dataflow','run_semgrep'],
      code: { 'scripts/report-utils.js': reportUtils },
    },
  },
  {
    caseId: 'M05',
    groundTruth: 'MALICIOUS',
    AI_ALONE: {
      task: 'security-review',
      context: 'PR #12 — taint-tracked command injection in scripts/report-utils.js',
      diff: PR12_DIFF_SUMMARY,
      code: { 'scripts/report-utils.js': reportUtils },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Resolve command injection via tainted base64 segment in scripts/report-utils.js',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      code: { 'scripts/report-utils.js': reportUtils },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel expediente PR #12. Inspect taint flow in scripts/report-utils.js.',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      availableTools: ['inspect_dataflow','run_codeql','inspect_source'],
      code: { 'scripts/report-utils.js': reportUtils },
    },
  },
  {
    caseId: 'M06',
    groundTruth: 'MALICIOUS',
    AI_ALONE: {
      task: 'security-review',
      context: 'PR #12 — package.json lifecycle hooks (prestart, postinstall)',
      diff: PR12_DIFF_SUMMARY,
      code: { 'package.json': packageJson },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Resolve supply-chain lifecycle hook candidates in package.json',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      code: { 'package.json': packageJson },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel expediente PR #12. Focus on package.json lifecycle hooks + their targets.',
      sentinelContext: SENTINEL_ASSISTED_CONTEXT_MALICIOUS,
      availableTools: ['inspect_package','inspect_source','inspect_dependencies'],
      code: { 'package.json': packageJson, 'scripts/health-check.js': healthCheck, 'scripts/report-utils.js': reportUtils },
    },
  },
  // --- BENIGN ---
  ...['B01','B02','B03','B04','B05','B06','B07','B08','B09','B10',
      'B11','B12','B13','B14','B15','B16','B17','B18','B19','B20'].map(id => {
    let manifest;
    try { manifest = readBenignCase(id); } catch(_) { manifest = { id, files: [] }; }
    const codeMap = {};
    for (const f of (manifest.files || [])) codeMap[f.path] = f.content;
    return {
      caseId: id,
      groundTruth: 'BENIGN',
      AI_ALONE: {
        task: 'security-review',
        context: `Standalone module: ${manifest.desc || id}`,
        code: codeMap,
      },
      SENTINEL_ASSISTED: {
        task: 'triage-sentinel-findings',
        context: `Sentinel scan of: ${manifest.desc || id}`,
        sentinelContext: {
          source: 'Sentinel CLI Local',
          cliFindings: [],
          cloudFindings: [],
          cloudMeta: { totalSignals: 0, actionableSignals: 0, observationOnly: 0, routingDecision: 'NO_ACTIONABLE_SENTINEL_FINDINGS' },
        },
        code: codeMap,
      },
      SENTINEL_AGENTIC: {
        task: 'sentinel-agentic-review',
        context: `Sentinel expediente: ${manifest.desc || id}. No actionable signals.`,
        sentinelContext: {
          source: 'Sentinel CLI Local',
          cliFindings: [],
          cloudFindings: [],
          cloudMeta: { totalSignals: 0, actionableSignals: 0, routingDecision: 'NO_ACTIONABLE_SENTINEL_FINDINGS' },
        },
        availableTools: ['inspect_source','inspect_package'],
        code: codeMap,
      },
    };
  }),
  // --- SEMANTIC PAIR ---
  {
    caseId: 'SP01a',
    groundTruth: 'BENIGN',
    pair: 'SP01',
    AI_ALONE: {
      task: 'security-review',
      context: 'Evaluate this JavaScript snippet for security issues',
      code: { 'snippet.js': 'const TEMPLATE = "(function(){ return 42; })()"; eval(TEMPLATE);' },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Sentinel flagged eval() usage. Determine if this is a real risk.',
      sentinelContext: {
        source: 'Sentinel CLI Local',
        cliFindings: [{ type: 'UNSAFE_EVAL', file: 'snippet.js', line: 1, severity: 'CRITICAL', title: 'eval() usage detected', snippet: 'eval(TEMPLATE)' }],
        cloudFindings: [],
      },
      code: { 'snippet.js': 'const TEMPLATE = "(function(){ return 42; })()"; eval(TEMPLATE);' },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel flagged eval() in snippet.js. Determine if input is closed or open.',
      sentinelContext: {
        cliFindings: [{ type: 'UNSAFE_EVAL', file: 'snippet.js', line: 1, severity: 'CRITICAL' }],
      },
      availableTools: ['inspect_source','inspect_dataflow'],
      code: { 'snippet.js': 'const TEMPLATE = "(function(){ return 42; })()"; eval(TEMPLATE);' },
    },
  },
  {
    caseId: 'SP01b',
    groundTruth: 'MALICIOUS',
    pair: 'SP01',
    AI_ALONE: {
      task: 'security-review',
      context: 'Evaluate this JavaScript snippet for security issues',
      code: { 'snippet.js': 'const userCode = req.body.code; eval(userCode);' },
    },
    SENTINEL_ASSISTED: {
      task: 'triage-sentinel-findings',
      context: 'Sentinel flagged eval() with external input. Determine the risk.',
      sentinelContext: {
        source: 'Sentinel CLI Local',
        cliFindings: [{ type: 'UNSAFE_EVAL', file: 'snippet.js', line: 1, severity: 'CRITICAL', title: 'eval() usage detected', snippet: 'eval(userCode)' }],
        cloudFindings: [],
      },
      code: { 'snippet.js': 'const userCode = req.body.code; eval(userCode);' },
    },
    SENTINEL_AGENTIC: {
      task: 'sentinel-agentic-review',
      context: 'Sentinel flagged eval() in snippet.js. Trace taint from req.body.code.',
      sentinelContext: {
        cliFindings: [{ type: 'UNSAFE_EVAL', file: 'snippet.js', line: 1, severity: 'CRITICAL' }],
      },
      availableTools: ['inspect_source','inspect_dataflow'],
      code: { 'snippet.js': 'const userCode = req.body.code; eval(userCode);' },
    },
  },
];

module.exports = { CASES };
