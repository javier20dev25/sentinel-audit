#!/usr/bin/env node
'use strict';
/** Sentinel Audit v1 command line.  Every advertised command does work. */
const fs = require('fs');
const path = require('path');
const { loadConfig } = require('./lib/core');
const { preflight, checkToolHealth, checkHostedHealth } = require('./workflow/preflight');
const { runAuditV1, rerenderExecution, rerouteExecution, cleanupExecution, continueSpecialists, loadExecution, exitCodeFor } = require('./workflow/pipeline-v1');
const { adjudicate, auditVerdict, openCandidates } = require('./correlate');
const { renderReport } = require('./reports/expediente');
const { writeJson, manifest, contained } = require('./workflow/artifacts');

const EXIT = Object.freeze({ COMPLETE: 0, CANDIDATES: 1, DEGRADED: 2, PREFLIGHT: 3, INFRA: 4 });
const VALUE_FLAGS = new Set(['repo', 'commit', 'routing', 'only', 'skip', 'output', 'max-heavy', 'max-light', 'timeout', 'name', 'candidate', 'disposition', 'rationale', 'severity', 'priority', 'ground-truth', 'provider', 'api']);
const BOOLEAN_FLAGS = new Set(['dry-run', 'keep-worktree', 'json', 'verbose', 'quiet', 'help', 'cloud']);
const PROVIDERS = new Set(['local', 'cloud']);
const COMMANDS = new Set(['preflight', 'run', 'scan', 'route', 'specialists', 'report', 'cleanup', 'adjudicate', 'doctor', 'resume', 'retry', 'help']);

function usage() {
  return [
    'Sentinel Audit v1',
    '  sentinel-audit preflight --repo <path> [--commit <40-sha>] [--json]',
    '  sentinel-audit run --repo <path> --commit <40-sha> [--routing file|directory|repo] [--only tools] [--skip tools] [--dry-run] [--output dir] [--keep-worktree] [--max-heavy n] [--max-light n] [--timeout 30s]',
    '  sentinel-audit run --repo <path> --commit <40-sha> --cloud [--api <url>]  # hosted provider, requires policies.hosted.enabled',
    '  sentinel-audit scan --repo <path> --commit <40-sha> [run flags]  # Stage A + routing only',
    '  sentinel-audit route <execution-dir> --routing file|directory|repo',
    '  sentinel-audit specialists <execution-dir> [--only codeql,semgrep] [--max-heavy n] [--max-light n] [--timeout 30s]',
    '  sentinel-audit resume <execution-dir> [--only tools]  |  retry <execution-dir> --only tool',
    '  sentinel-audit report <execution-dir> | cleanup <execution-dir> | adjudicate <execution-dir> --candidate ID --disposition VALUE --rationale TEXT | doctor',
    '',
    'Flags: --repo --commit --routing --only --skip --dry-run --output --keep-worktree --max-heavy --max-light --timeout --cloud --provider local|cloud --api --json --verbose --quiet',
    'Exit codes: 0 COMPLETE; 1 FINDINGS/CANDIDATES; 2 DEGRADED/INCOMPLETE; 3 PREFLIGHT/CONFIG; 4 UNRECOVERABLE INFRASTRUCTURE.',
  ].join('\n');
}

function parse(argv) {
  const args = argv.slice(2);
  const command = args.shift() || 'doctor';
  if (!COMMANDS.has(command) && command !== '--help' && command !== '-h') throw new Error(`unknown command: ${command}`);
  const flags = {};
  const positional = [];
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (!value.startsWith('--')) { positional.push(value); continue; }
    const key = value.slice(2);
    if (!VALUE_FLAGS.has(key) && !BOOLEAN_FLAGS.has(key)) throw new Error(`unsupported flag: --${key}`);
    if (BOOLEAN_FLAGS.has(key)) { flags[key] = true; continue; }
    const next = args[++index];
    if (next == null || next.startsWith('--')) throw new Error(`--${key} requires a value`);
    flags[key] = next;
  }
  return { command: command === '--help' || command === '-h' ? 'help' : command, flags, positional };
}

function list(value) { return value ? String(value).split(',').map((item) => item.trim()).filter(Boolean) : []; }
function integer(value, flag) {
  if (value == null) return null;
  if (!/^\d+$/.test(String(value)) || Number(value) < 1) throw new Error(`--${flag} must be a positive integer`);
  return Number(value);
}
function duration(value) {
  if (value == null) return null;
  const match = String(value).trim().match(/^(\d+)(ms|s|m)?$/i);
  if (!match) throw new Error('--timeout must be an integer optionally followed by ms, s, or m');
  const n = Number(match[1]);
  return n * ((match[2] || 'ms').toLowerCase() === 'm' ? 60000 : (match[2] || '').toLowerCase() === 's' ? 1000 : 1);
}
function repoArgument(parsed) {
  const repo = parsed.flags.repo || parsed.positional[0];
  if (!repo) throw new Error('--repo or one repository path is required');
  if (parsed.flags.repo && parsed.positional.length) throw new Error('use either --repo or a positional repository path, not both');
  return repo;
}
function executionArgument(parsed) {
  const value = parsed.positional[0] || parsed.flags.repo;
  if (!value) throw new Error('execution directory is required');
  if (parsed.positional.length > 1) throw new Error('only one execution directory is allowed');
  return fs.statSync(value).isFile() ? path.dirname(value) : value;
}
function options(parsed) {
  return {
    name: parsed.flags.name,
    commit: parsed.flags.commit,
    routing: parsed.flags.routing,
    only: list(parsed.flags.only),
    skip: list(parsed.flags.skip),
    output: parsed.flags.output,
    dryRun: !!parsed.flags['dry-run'],
    keepWorktree: !!parsed.flags['keep-worktree'],
    maxHeavy: integer(parsed.flags['max-heavy'], 'max-heavy'),
    maxLight: integer(parsed.flags['max-light'], 'max-light'),
    timeoutMs: duration(parsed.flags.timeout),
    provider: parsed.flags.cloud ? 'cloud' : (parsed.flags.provider || null),
    apiUrl: parsed.flags.api || null,
  };
}

function selectedProvider(opts) {
  const requested = opts.provider;
  if (requested == null) return null;
  if (!PROVIDERS.has(requested)) throw new Error(`--provider must be local or cloud (got ${requested})`);
  return requested;
}
function print(value, asJson, quiet = false) {
  if (quiet) return;
  if (asJson) console.log(JSON.stringify(value, null, 2));
  else if (typeof value === 'string') console.log(value);
  else console.log(JSON.stringify(value, null, 2));
}
function executionSummary(result) {
  const e = result.expediente;
  return {
    executionId: e.executionId,
    executionDir: result.executionDir,
    pipelineStatus: e.pipelineStatus,
    verdict: e.auditVerdict && e.auditVerdict.verdict,
    analysisState: e.auditVerdict && e.auditVerdict.analysisState,
    canClaimClean: e.auditVerdict && e.auditVerdict.canClaimClean,
    candidates: e.auditVerdict && e.auditVerdict.candidateCount,
    cleanup: e.cleanup && e.cleanup.cleanupStatus,
    exitCode: result.exitCode,
  };
}

async function main() {
  const parsed = parse(process.argv);
  const opts = options(parsed);
  if (parsed.command === 'help' || parsed.flags.help) { console.log(usage()); return EXIT.COMPLETE; }
  if (parsed.command === 'doctor') {
    const { tools, policies } = loadConfig();
    const health = checkToolHealth(tools);
    const output = { cloud: health.sentinel, hosted: checkHostedHealth(tools, policies), specialists: Object.fromEntries(Object.entries(health).filter(([name]) => name !== 'sentinel')), resources: policies.resources, publication: policies.publication };
    print(output, !!parsed.flags.json, !!parsed.flags.quiet);
    return health.sentinel && health.sentinel.available ? EXIT.COMPLETE : EXIT.PREFLIGHT;
  }
  if (parsed.command === 'preflight') {
    const repos = parsed.flags.repo ? [parsed.flags.repo] : parsed.positional;
    if (!repos.length) throw new Error('preflight requires --repo or one or more positional repository paths');
    const rows = repos.map((repo) => preflight(repo, { commit: opts.commit, name: opts.name }));
    print(rows, !!parsed.flags.json, !!parsed.flags.quiet);
    return rows.some((row) => row.verdict === 'SKIP') ? EXIT.PREFLIGHT : rows.some((row) => row.verdict === 'AUDIT_LIMITED') ? EXIT.DEGRADED : EXIT.COMPLETE;
  }
  if (parsed.command === 'run' || parsed.command === 'scan') {
    if (parsed.flags.cloud && parsed.flags.provider && parsed.flags.provider !== 'cloud') throw new Error(`--cloud selects the hosted provider and conflicts with --provider ${parsed.flags.provider}`);
    const provider = selectedProvider(opts) || 'local';
    if (parsed.command === 'scan' && provider === 'cloud') throw new Error('--cloud is only supported by run; scan is Stage A + routing only');
    const result = await runAuditV1(repoArgument(parsed), Object.assign(opts, { scanOnly: parsed.command === 'scan', provider }));
    print(executionSummary(result), !!parsed.flags.json, !!parsed.flags.quiet);
    return result.exitCode;
  }
  if (parsed.command === 'route') {
    if (!opts.routing) throw new Error('route requires --routing file|directory|repo');
    const result = rerouteExecution(executionArgument(parsed), opts);
    print(executionSummary(result), !!parsed.flags.json, !!parsed.flags.quiet);
    return result.exitCode;
  }
  if (parsed.command === 'report') {
    const result = rerenderExecution(executionArgument(parsed));
    print(executionSummary(result), !!parsed.flags.json, !!parsed.flags.quiet);
    return result.exitCode;
  }
  if (parsed.command === 'cleanup') {
    const result = cleanupExecution(executionArgument(parsed), opts);
    print(executionSummary(result), !!parsed.flags.json, !!parsed.flags.quiet);
    return result.exitCode;
  }
  if (parsed.command === 'specialists' || parsed.command === 'resume' || parsed.command === 'retry') {
    if (parsed.command === 'retry' && !opts.only.length) throw new Error('retry requires --only <tool>');
    const result = await continueSpecialists(executionArgument(parsed), opts);
    print(executionSummary(result), !!parsed.flags.json, !!parsed.flags.quiet);
    return result.exitCode;
  }
  if (parsed.command === 'adjudicate') {
    const { root, expediente } = loadExecution(executionArgument(parsed));
    const candidate = (expediente.candidates || []).find((item) => item.candidateId === parsed.flags.candidate);
    if (!candidate) throw new Error(`candidate not found: ${parsed.flags.candidate || '(missing --candidate)'}`);
    const { policies } = loadConfig();
    if (!parsed.flags.disposition || !policies.dispositions.includes(parsed.flags.disposition)) throw new Error('--disposition must be a configured disposition');
    if (!parsed.flags.rationale) throw new Error('--rationale is required for a human adjudication');
    adjudicate(candidate, { disposition: parsed.flags.disposition, state: 'MANUALLY_VERIFIED', severity: parsed.flags.severity, priority: parsed.flags.priority, rationale: parsed.flags.rationale, groundTruth: parsed.flags['ground-truth'] });
    expediente.adjudications = [...(expediente.adjudications || []), { candidateId: candidate.candidateId, at: new Date().toISOString(), by: 'human', disposition: candidate.disposition, rationale: candidate.rationale }];
    expediente.auditVerdict = auditVerdict(Object.values(expediente.tools || {}), openCandidates(expediente.candidates));
    writeJson(contained(root, 'expediente.json'), expediente, { overwrite: true });
    writeJson(contained(root, 'report', 'REPORT.json'), expediente, { overwrite: true });
    renderReport(expediente);
    manifest(root, { pipelineStatus: expediente.pipelineStatus, adjudicated: candidate.candidateId });
    const result = { executionDir: root, expediente, exitCode: exitCodeFor(expediente) };
    print(executionSummary(result), !!parsed.flags.json, !!parsed.flags.quiet);
    return result.exitCode;
  }
  throw new Error(`command is not implemented: ${parsed.command}`);
}

if (require.main === module) {
  main()
    .then((code) => { process.exitCode = code; })
    .catch((error) => { console.error(`sentinel-audit: ${error && error.message || error}`); process.exitCode = EXIT.INFRA; });
}

module.exports = { parse, options, duration, integer, usage, EXIT, main };
