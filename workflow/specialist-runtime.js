'use strict';
/**
 * Real specialist adapters for the v1 scheduler.
 *
 * They invoke only static-analysis commands with shell=false.  A tool that is
 * not usable in this host returns an explicit UNAVAILABLE envelope; it never
 * becomes an empty successful scan.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { fileURLToPath } = require('url');
const { STATUS, envelope, snippet, dirBytes } = require('../lib/core');
const { resolveTool, probeVersion, executeProcess, JOB_STATE } = require('./tooling');
const { contained, writeJson } = require('./artifacts');

const processStatus = (state) => ({
  [JOB_STATE.SUCCEEDED]: STATUS.SUCCESS,
  [JOB_STATE.TIMEOUT]: STATUS.TIMEOUT,
  [JOB_STATE.CANCELLED]: STATUS.CANCELLED,
  [JOB_STATE.UNAVAILABLE]: STATUS.UNAVAILABLE,
  [JOB_STATE.FAILED]: STATUS.ERROR,
}[state] || STATUS.ERROR);

const coverageUnknown = (errors = []) => ({
  filesSeen: null, filesEligible: null, filesParsed: null, analysisCompleted: false,
  coverageKnown: false, coverageUnknown: true, engineCoverage: 'SPECIALIST_COVERAGE_UNMEASURED', errors,
});

// Several tools exit non-zero while still printing their JSON, and the useful
// explanation is usually the last error line rather than the whole stream.
const PROGRESS_LINE = /^(scanning dir|starting filesystem walk|scanned\b|end status:|found \d+ packages|warning:|loading|fetching|analyzing)\b/i;
function reasonFromStderr(stderr) {
  if (!stderr) return null;
  const lines = String(stderr).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const errors = lines.filter((line) => !PROGRESS_LINE.test(line) && /^(error|fatal|failed|unable|could not|cannot|panic)\b/i.test(line));
  if (errors.length) return errors[errors.length - 1].slice(0, 500);
  // No recognisable error line: a progress or warning tail would be misleading,
  // so report nothing rather than invent a reason.
  return null;
}

// osv-scanner exits 0 for "nothing found" and 1 for "vulnerabilities found";
// genuine tool failures surface at 128 and above.
function osvExitSucceeded(result) {
  return !!result && (result.status === 0 || result.status === 1);
}

const { abs, relTarget, realContained } = require('./paths');

/**
 * The four outcomes a specialist can have, stated explicitly.
 *
 * These are deliberately distinct.  A tool that was never installed and a tool
 * that ran and crashed both used to reduce to "no findings", which is the one
 * reading an audit must never produce: the first means the repository was never
 * examined, the second means it was examined and the examination broke.
 *
 *   AVAILABLE   the tool ran and reported
 *   UNAVAILABLE the tool could not be run on this host, so nothing was examined
 *   FAILED      the tool ran and did not complete
 *   TIMEOUT     the tool ran out of its budget and was terminated
 */
const OUTCOME = Object.freeze({ AVAILABLE: 'AVAILABLE', UNAVAILABLE: 'UNAVAILABLE', FAILED: 'FAILED', TIMEOUT: 'TIMEOUT' });

function specialistOutcome(result) {
  if (!result) return OUTCOME.FAILED;
  const job = result.job || {};
  const state = job.state || result.status;
  if (state === JOB_STATE.UNAVAILABLE || result.status === STATUS.UNAVAILABLE) return OUTCOME.UNAVAILABLE;
  if (state === JOB_STATE.TIMEOUT || result.status === STATUS.TIMEOUT || (result.cost && result.cost.timedOut)) return OUTCOME.TIMEOUT;
  if (state === JOB_STATE.CANCELLED || result.status === STATUS.CANCELLED) return OUTCOME.FAILED;
  if (result.status === STATUS.ERROR || result.status === STATUS.INVALID || state === JOB_STATE.FAILED) return OUTCOME.FAILED;
  return OUTCOME.AVAILABLE;
}

function jobEnvelope(tool, resolution, job, error, extra = {}) {
  return envelope(tool, {
    status: STATUS.UNAVAILABLE,
    availability: resolution,
    error: error || (resolution && resolution.reason) || `${tool} unavailable`,
    coverage: coverageUnknown([error || (resolution && resolution.reason) || `${tool} unavailable`]),
    cost: { wallClockMs: 0, timedOut: false },
    job: Object.assign({ resourceClass: tool === 'codeql' ? 'HEAVY' : 'LIGHT', state: JOB_STATE.UNAVAILABLE }, job || {}),
    notes: ['specialist did not execute; this is a coverage gap and not a clean result'],
    ...extra,
  });
}

function rawDirectory(ctx, tool) {
  const dir = contained(ctx.work, 'specialists', tool, 'raw');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function recordProcess(dir, label, result) {
  return writeJson(contained(dir, `${label}.json`), result);
}

async function resolutionFor(tool, ctx, job) {
  const base = (ctx.toolResolutions && ctx.toolResolutions[tool]) || resolveTool(tool, ctx.tools[tool] || {}, { overrides: ctx.toolOverrides });
  if (!base.available) return base;
  // The probe cap is the tool's own budget, not a hard 15s: a Python launcher
  // under a loaded host can exceed that and a timeout here silently removes a
  // working tool from the audit.
  return probeVersion(base, { timeoutMs: Math.min(60000, ctx.timeoutFor(tool)), signal: job && job.signal });
}

async function execute(tool, ctx, job, command, args, label, cwd) {
  const dir = rawDirectory(ctx, tool);
  const result = await executeProcess(command, args, {
    cwd: cwd || ctx.root,
    timeoutMs: ctx.timeoutFor(tool),
    graceMs: ctx.policies.resources.gracefulTerminationMs,
    signal: job && job.signal,
    queuedAt: job && job.queuedAt,
  });
  // Process records are written with an exclusive create, so a label that only
  // names the phase collides the moment the same tool is retried.  Deriving the
  // name from the job id keeps every attempt's evidence and makes a retry a
  // genuine re-run rather than an overwrite.
  const attempt = job && job.id ? require('crypto').createHash('sha256').update(String(job.id)).digest('hex').slice(0, 8) : 'nojob';
  recordProcess(dir, `${label}-${attempt}`, { command: path.basename(command), args, ...result });
  return result;
}

function standardJob(job, tool, state, process) {
  return {
    jobId: job.id,
    resourceClass: job.resourceClass,
    state,
    queuedAt: job.queuedAt,
    startedAt: process && process.startedAt || job.startedAt,
    finishedAt: process && process.finishedAt || new Date().toISOString(),
    durationMs: process && process.durationMs || 0,
    timeoutMs: process && process.timeoutMs || null,
    terminationRequested: !!(process && process.terminationRequested),
    terminationConfirmed: !!(process && process.terminationConfirmed),
    forceKilled: !!(process && process.forceKilled),
  };
}

function sarifArtifact(root, uri) {
  if (typeof uri !== 'string' || !uri) return null;
  let candidate = uri;
  if (/^file:/i.test(candidate)) {
    try { candidate = fileURLToPath(candidate); } catch (_) { return null; }
  }
  if (process.platform === 'win32') candidate = candidate.replace(/^\/([A-Za-z]:\/)/, '$1');
  if (path.isAbsolute(candidate)) {
    const relative = path.relative(path.resolve(root), path.resolve(candidate));
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return null;
    candidate = relative || '.';
  }
  return abs(root, candidate);
}

function parseSarif(root, sarif, options = {}) {
  const tool = options.tool || 'codeql';
  const kind = options.kind || 'dataflow';
  const result = [];
  for (const run of sarif.runs || []) for (const entry of run.results || []) {
    const location = ((entry.locations || [])[0] || {}).physicalLocation || {};
    const file = sarifArtifact(root, location.artifactLocation && location.artifactLocation.uri);
    const line = location.region && location.region.startLine || null;
    result.push({
      tool, kind, rule: entry.ruleId || null, level: entry.level || null,
      file, line, endLine: location.region && location.region.endLine || null,
      detail: String(entry.message && entry.message.text || '').split(/\r?\n/)[0].slice(0, 300),
      snippet: snippet(root, file, line),
      path: Array.isArray(entry.codeFlows) && entry.codeFlows[0] && entry.codeFlows[0].threadFlows
        ? entry.codeFlows[0].threadFlows[0].locations.map((step) => ({
          file: sarifArtifact(root, step.location && step.location.physicalLocation && step.location.physicalLocation.artifactLocation && step.location.physicalLocation.artifactLocation.uri),
          line: step.location && step.location.physicalLocation && step.location.physicalLocation.region && step.location.physicalLocation.region.startLine || null,
          message: String(step.location && step.location.message && step.location.message.text || '').split(/\r?\n/)[0].slice(0, 160),
        })) : null,
    });
  }
  return result;
}

async function codeql(root, ctx, job, opts = {}) {
  const resolution = await resolutionFor('codeql', ctx, job);
  if (!resolution.available) return jobEnvelope('codeql', resolution, standardJob(job, 'codeql', JOB_STATE.UNAVAILABLE));
  const language = opts.language || (ctx.inv && ctx.inv.mainLanguage);
  const suite = ctx.tools.codeql.suites && ctx.tools.codeql.suites[language];
  if (!suite || !fs.existsSync(require('../lib/core').expand(suite))) {
    return envelope('codeql', { status: STATUS.INVALID, availability: resolution, error: `CodeQL query suite unavailable for language ${language || 'unknown'}`, coverage: coverageUnknown(['query suite missing']), job: standardJob(job, 'codeql', JOB_STATE.FAILED) });
  }
  const db = contained(ctx.work, 'temporary', 'codeql-db');
  // CodeQL refuses to create the database when the parent directory is missing.
  fs.mkdirSync(path.dirname(db), { recursive: true });
  const sarif = contained(ctx.work, 'specialists', 'codeql', 'raw', 'codeql.sarif');
  fs.mkdirSync(path.dirname(sarif), { recursive: true });
  const ram = opts.ram || ctx.policies.budget.codeqlDefaultRam;
  const create = await execute('codeql', ctx, job, resolution.path, [
    'database', 'create', `--language=${language}`, '--build-mode=none', '--overwrite', `--ram=${ram}`,
    `--source-root=${root}`, '--', db,
  ], 'database-create', root);
  if (!create.ok) return envelope('codeql', {
    status: processStatus(create.state), availability: resolution, error: create.error || create.stderr || 'database create failed',
    coverage: coverageUnknown(['database create did not complete']), cost: { wallClockMs: create.durationMs, timedOut: create.timedOut },
    job: standardJob(job, 'codeql', create.state, create), rawArtifact: rawDirectory(ctx, 'codeql'),
  });
  // Order matters: a finalized CodeQL database can no longer be analyzed, so the
  // sequence is create -> analyze -> finalize.  Finalizing before analyzing fails
  // with "Database ... is already finalized" and would report a tool error for a
  // repository that was never actually examined.
  const analyze = await execute('codeql', ctx, job, resolution.path, [
    'database', 'analyze', `--ram=${ram}`, '--format=sarif-latest', `--output=${sarif}`, '--no-print-diagnostics-summary', '--', db, require('../lib/core').expand(suite),
  ], 'database-analyze', root);
  // Finalize runs even when analysis failed so the database is not left in a
  // half-created state for the next attempt.
  const finalize = await execute('codeql', ctx, job, resolution.path, ['database', 'finalize', `--ram=${ram}`, db], 'database-finalize', root);
  const wallClockMs = create.durationMs + analyze.durationMs + finalize.durationMs;
  if (!fs.existsSync(sarif)) {
    cleanupDb(db, ctx.keepDb);
    return envelope('codeql', {
      status: processStatus(analyze.state), availability: resolution, error: analyze.error || analyze.stderr || 'CodeQL produced no SARIF',
      coverage: coverageUnknown(['missing SARIF is a tool failure, not zero findings']), cost: { wallClockMs, timedOut: analyze.timedOut },
      job: standardJob(job, 'codeql', analyze.state, analyze), rawArtifact: rawDirectory(ctx, 'codeql'),
      notes: finalize.ok ? [] : [`database finalize failed: ${finalize.stderr || finalize.error}`],
    });
  }
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(sarif, 'utf8')); }
  catch (error) { cleanupDb(db, ctx.keepDb); return envelope('codeql', { status: STATUS.ERROR, availability: resolution, error: `invalid SARIF: ${error.message}`, coverage: coverageUnknown(['invalid SARIF']), rawArtifact: sarif, job: standardJob(job, 'codeql', JOB_STATE.FAILED, analyze) }); }
  const findings = parseSarif(root, parsed);
  const cleanup = cleanupDb(db, ctx.keepDb);
  return envelope('codeql', {
    status: analyze.ok && cleanup.ok ? STATUS.PARTIAL : processStatus(analyze.state), availability: resolution,
    version: resolution.version, findings, rawArtifact: sarif,
    coverage: Object.assign(coverageUnknown(['CodeQL SARIF does not attest a parsed-file denominator']), { analysisCompleted: true }),
    cost: { wallClockMs, timedOut: analyze.timedOut, dbBytes: cleanup.beforeBytes, dbDiscardedBytes: cleanup.discardedBytes },
    job: standardJob(job, 'codeql', analyze.state, analyze), notes: cleanup.errors,
  });
}

function cleanupDb(db, keep) {
  if (!fs.existsSync(db)) return { ok: true, errors: [], beforeBytes: 0, discardedBytes: 0 };
  const beforeBytes = dirBytes(db);
  if (keep) return { ok: true, errors: ['CodeQL database retained by --keep-worktree'], beforeBytes, discardedBytes: 0 };
  try { fs.rmSync(db, { recursive: true, force: false, maxRetries: 1, retryDelay: 100 }); return { ok: true, errors: [], beforeBytes, discardedBytes: beforeBytes }; }
  catch (error) { return { ok: false, errors: [`CodeQL db cleanup failed: ${error.message}`], beforeBytes, discardedBytes: 0 }; }
}

/**
 * Resolve the configured rulesets to absolute paths.  The scan runs with cwd
 * set to the audited repository, so a repo-relative config path would not
 * resolve there and semgrep would exit with a usage error.  Remote rulesets are
 * rejected outright: they are not reproducible.
 */
function localSemgrepConfigs(ctx) {
  const base = ctx.auditRoot || process.cwd();
  return (ctx.tools.semgrep.configs || [])
    .filter((config) => !/^p\//i.test(config))
    .map((config) => path.resolve(base, config))
    .filter((resolved) => fs.existsSync(resolved));
}

/**
 * Semgrep namespaces every local rule id with a dotted path derived from where
 * the config file lives (it strips the home directory, then dots the rest and
 * drops the filename).  Loading the same ruleset from two different locations
 * therefore yields different check_ids, which would leak the install layout into
 * finding identity and make the same commit produce different candidate ids on
 * two hosts.
 *
 * Every vendored rule id must begin with the namespace declared in
 * config/tools.json, so the stable identity is the suffix starting at the last
 * occurrence of that namespace.  When the namespace is absent the id is left
 * untouched rather than guessed at.
 */
const SEMGREP_ID_NAMESPACE = 'sentinel.';

function normalizeSemgrepRuleId(checkId) {
  const raw = String(checkId || '');
  const at = raw.lastIndexOf(SEMGREP_ID_NAMESPACE);
  if (at < 0) return raw;
  return raw.slice(at);
}

/**
 * Semgrep aborts the whole run when any target is not a readable path, and in
 * that case it still prints JSON with `results: []` plus the real reason in
 * `errors`, then exits non-zero.  Trusting the exit code alone therefore turns
 * one bad path into "zero findings for the entire repository", which is the
 * single most dangerous way this adapter could fail.  Targets are filtered up
 * front, the per-root errors are surfaced, and a non-zero exit that still carries
 * parseable results is kept as a partial result instead of being discarded.
 *
 * All three routing modes are supported here, because the modes differ in what
 * they hand to the tool rather than in whether the tool can be given it:
 *
 *   file       a regular file
 *   directory  a directory, scanned recursively by the engine
 *   repo       the repository root itself, expressed as '.'
 *
 * Rejecting a directory here was what made `--routing directory` and
 * `--routing repo` silently scan nothing while still reporting a result.
 * Containment is checked on the real path, so a symlink or junction inside the
 * repository cannot be used to reach a target outside it.
 */
function usableTargets(root, targets) {
  const usable = [];
  const rejected = [];
  for (const target of targets) {
    // An empty target is a defect in the caller, not an implicit request for the
    // whole repository.  It has to be rejected before the '.' handling below,
    // otherwise a blank entry silently widens the scan to every file.
    if (!target || typeof target !== 'string') { rejected.push({ target: String(target), reason: 'empty target' }); continue; }
    if (target === '.') {
      // The repository root is the identity a repo-scoped target carries.
      const rootAbsolute = path.resolve(root);
      const check = realContained(root, rootAbsolute);
      if (!check.ok) { rejected.push({ target: '.', reason: check.reason }); continue; }
      let stat = null;
      try { stat = fs.statSync(rootAbsolute); } catch (error) { rejected.push({ target: '.', reason: `unreadable: ${error.code || error.message}` }); continue; }
      if (!stat.isDirectory()) { rejected.push({ target: '.', reason: 'repository root is not a directory' }); continue; }
      usable.push(rootAbsolute);
      continue;
    }
    const absolute = abs(root, target);
    if (!absolute) { rejected.push({ target, reason: 'outside the audited repository' }); continue; }
    let stat = null;
    try { stat = fs.statSync(absolute); } catch (error) { rejected.push({ target, reason: `unreadable: ${error.code || error.message}` }); continue; }
    if (!stat.isFile() && !stat.isDirectory()) { rejected.push({ target, reason: 'not a regular file or directory' }); continue; }
    const check = realContained(root, absolute);
    if (!check.ok) { rejected.push({ target, reason: check.reason }); continue; }
    usable.push(absolute);
  }
  return { usable, rejected };
}

function semgrepTargetNotes(rejected, engineErrors) {
  const notes = [];
  for (const item of rejected) notes.push(`target rejected (${item.reason}): ${item.target}`);
  for (const item of engineErrors || []) notes.push(`semgrep engine error: ${item && item.message ? item.message : JSON.stringify(item)}`);
  return notes;
}

async function semgrep(root, ctx, job, opts = {}) {
  const resolution = await resolutionFor('semgrep', ctx, job);
  if (!resolution.available) return jobEnvelope('semgrep', resolution, standardJob(job, 'semgrep', JOB_STATE.UNAVAILABLE));
  const configs = localSemgrepConfigs(ctx);
  if (!configs.length) return jobEnvelope('semgrep', { ...resolution, available: false, state: 'UNAVAILABLE', reason: 'no local Semgrep rules configured; remote rules are disabled' }, standardJob(job, 'semgrep', JOB_STATE.UNAVAILABLE));
  const requested = opts.targets && opts.targets.length ? opts.targets : [root];
  const { usable, rejected } = usableTargets(root, requested);
  const notes = semgrepTargetNotes(rejected, []);
  if (!usable.length) return envelope('semgrep', {
    status: STATUS.PARTIAL, availability: resolution, version: resolution.version, findings: [],
    coverage: Object.assign(coverageUnknown(['no usable scan target survived validation']), { analysisCompleted: false, targetsRequested: requested.length, targetsRejected: rejected.length }),
    job: standardJob(job, 'semgrep', JOB_STATE.FAILED, { state: JOB_STATE.FAILED }), notes,
  });
  const targets = usable;
  const findings = [];
  const engineErrors = [];
  let totalMs = 0;
  let failed = null;
  const raw = rawDirectory(ctx, 'semgrep');
  for (const config of configs) {
    // No --offline: semgrep 1.175 rejects it as an unknown option and exits with
    // a usage error.  Remote access is already excluded by localSemgrepConfigs().
    const result = await execute('semgrep', ctx, job, resolution.path, [
      'scan', '--config', config, '--json', '--quiet', '--metrics=off', '--disable-version-check', '--no-git-ignore', '--', ...targets,
    ], `scan-${crypto.createHash('sha256').update(config).digest('hex').slice(0, 12)}`, root);
    totalMs += result.durationMs;
    // Parse before deciding on the exit code: a non-zero exit can still carry the
    // findings for the roots that did scan.
    let json = null;
    try { json = JSON.parse(result.stdout); }
    catch (error) { json = null; }
    if (!json) { if (!result.ok) { failed = result; break; } failed = { ...result, state: JOB_STATE.FAILED, error: `invalid Semgrep JSON: ${result.error || 'unparseable output'}` }; break; }
    for (const item of json.errors || []) engineErrors.push(item);
    if (!result.ok && !(json.results || []).length) { failed = { ...result, state: JOB_STATE.FAILED, error: `Semgrep exited ${result.exitCode == null ? 'non-zero' : result.exitCode} and reported no results: ${(json.errors || []).map((e) => e && e.message).filter(Boolean).join('; ') || result.stderr || 'unknown'}` }; break; }
    for (const item of json.results || []) {
      const file = abs(root, item.path);
      const line = item.start && item.start.line || null;
      findings.push({ tool: 'semgrep', kind: 'pattern', rule: normalizeSemgrepRuleId(item.check_id), level: item.extra && item.extra.severity || null, file, line, endLine: item.end && item.end.line || null, detail: String(item.extra && item.extra.message || '').split(/\r?\n/)[0].slice(0, 300), snippet: snippet(root, file, line) });
    }
  }
  const allNotes = semgrepTargetNotes(rejected, engineErrors);
  if (failed) return envelope('semgrep', { status: processStatus(failed.state), availability: resolution, error: failed.error || failed.stderr || 'Semgrep failed', coverage: coverageUnknown(['Semgrep did not complete']), cost: { wallClockMs: totalMs, timedOut: failed.timedOut }, rawArtifact: raw, job: standardJob(job, 'semgrep', failed.state, failed), notes: allNotes });
  return envelope('semgrep', {
    status: STATUS.PARTIAL, availability: resolution, version: resolution.version, findings, rawArtifact: raw,
    coverage: Object.assign(coverageUnknown(['Semgrep does not expose a trustworthy parsed-file denominator']), { analysisCompleted: true, targetsRequested: requested.length, targetsRejected: rejected.length, engineErrors: engineErrors.length }),
    cost: { wallClockMs: totalMs }, job: standardJob(job, 'semgrep', JOB_STATE.SUCCEEDED), notes: allNotes,
  });
}

async function trivy(root, ctx, job) {
  const resolution = await resolutionFor('trivy', ctx, job);
  if (!resolution.available) return jobEnvelope('trivy', resolution, standardJob(job, 'trivy', JOB_STATE.UNAVAILABLE));
  const output = contained(ctx.work, 'specialists', 'trivy', 'raw', 'trivy.json');
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const args = ['fs', '--format', 'json', `--output=${output}`, '--scanners', ctx.tools.trivy.scanners, '--skip-dirs', 'node_modules,.git', '--quiet'];
  if (ctx.tools.trivy.offline) args.push('--skip-db-update', '--skip-java-db-update');
  args.push(root);
  const result = await execute('trivy', ctx, job, resolution.path, args, 'scan', root);
  if (!fs.existsSync(output)) return envelope('trivy', { status: processStatus(result.state), availability: resolution, error: result.error || result.stderr || 'Trivy produced no JSON', coverage: coverageUnknown(['missing Trivy JSON']), cost: { wallClockMs: result.durationMs, timedOut: result.timedOut }, rawArtifact: rawDirectory(ctx, 'trivy'), job: standardJob(job, 'trivy', result.state, result) });
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(output, 'utf8')); }
  catch (error) { return envelope('trivy', { status: STATUS.ERROR, availability: resolution, error: `invalid Trivy JSON: ${error.message}`, coverage: coverageUnknown(['invalid Trivy JSON']), rawArtifact: output, job: standardJob(job, 'trivy', JOB_STATE.FAILED, result) }); }
  const findings = [];
  for (const entry of parsed.Results || []) {
    for (const item of entry.Vulnerabilities || []) findings.push({ tool: 'trivy', kind: 'sca', rule: item.VulnerabilityID, level: item.Severity, file: abs(root, entry.Target), detail: `${item.PkgName}@${item.InstalledVersion}${item.FixedVersion ? ` fixed in ${item.FixedVersion}` : ''}` });
    for (const item of entry.Misconfigurations || []) findings.push({ tool: 'trivy', kind: 'misconfig', rule: item.ID, level: item.Severity, file: abs(root, entry.Target), detail: String(item.Title || '').slice(0, 300) });
    // Trivy 0.74 leaves Secrets[].Target empty and only fills it on the parent
    // Results[] entry.  Without the fallback every secret arrives with a null
    // file, which makes it impossible to scope, deduplicate or verify, and the
    // finding would be silently unusable.
    for (const item of entry.Secrets || []) findings.push({ tool: 'trivy', kind: 'secret', rule: item.RuleID, level: item.Severity, file: abs(root, item.Target || entry.Target), line: item.StartLine || null, detail: 'secret detected (value redacted)', secret: true });
  }
  return envelope('trivy', { status: result.ok ? STATUS.PARTIAL : processStatus(result.state), availability: resolution, version: resolution.version, findings, rawArtifact: output, coverage: Object.assign(coverageUnknown(['Trivy does not expose a parsed-file denominator']), { analysisCompleted: result.ok }), cost: { wallClockMs: result.durationMs, timedOut: result.timedOut }, job: standardJob(job, 'trivy', result.state, result) });
}

async function osv(root, ctx, job) {
  const resolution = await resolutionFor('osv', ctx, job);
  if (!resolution.available) return jobEnvelope('osv', resolution, standardJob(job, 'osv', JOB_STATE.UNAVAILABLE));
  if (!(ctx.inv.lockfiles || []).length) return envelope('osv', { status: STATUS.SKIPPED, notApplicable: true, availability: resolution, coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true, coverageKnown: false, coverageUnknown: true, errors: [] }, notes: ['no lockfile: OSV is not applicable'], job: standardJob(job, 'osv', JOB_STATE.SUCCEEDED) });
  const output = contained(ctx.work, 'specialists', 'osv', 'raw', 'osv.json');
  fs.mkdirSync(path.dirname(output), { recursive: true });
  // OSV 2.x deprecated --output in favour of --output-file.
  const args = ['scan', 'source', '--format', 'json', `--output-file=${output}`];
  if (ctx.tools.osv.offline) args.push('--offline');
  args.push(root);
  const result = await execute('osv', ctx, job, resolution.path, args, 'scan', root);
  if (!fs.existsSync(output)) return envelope('osv', { status: processStatus(result.state), availability: resolution, error: result.error || result.stderr || 'OSV produced no JSON', coverage: coverageUnknown(['missing OSV JSON']), cost: { wallClockMs: result.durationMs, timedOut: result.timedOut }, rawArtifact: rawDirectory(ctx, 'osv'), job: standardJob(job, 'osv', result.state, result) });
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(output, 'utf8')); }
  catch (error) { return envelope('osv', { status: STATUS.ERROR, availability: resolution, error: `invalid OSV JSON: ${error.message}`, coverage: coverageUnknown(['invalid OSV JSON']), rawArtifact: output, job: standardJob(job, 'osv', JOB_STATE.FAILED, result) }); }
  const findings = [];
  for (const record of parsed.results || []) {
    // Attribute a dependency signal to the manifest OSV actually parsed. Do not
    // invent package.json for Maven, Cargo, Go, or any other lockfile result.
    const reportedPath = record.source && typeof record.source.path === 'string' ? record.source.path : '';
    const resolvedPath = reportedPath ? path.resolve(root, reportedPath) : null;
    const relativePath = resolvedPath ? path.relative(path.resolve(root), resolvedPath) : '';
    const sourceFile = relativePath && relativePath !== '..' && !relativePath.startsWith(`..${path.sep}`) && !path.isAbsolute(relativePath) ? resolvedPath : null;
    for (const pkg of record.packages || []) for (const vulnerability of pkg.vulnerabilities || []) findings.push({ tool: 'osv', kind: 'sca', rule: vulnerability.id, level: (vulnerability.severity || []).map((score) => score.score).join(','), file: sourceFile, detail: `${pkg.package && (pkg.package.name || pkg.package.source) || '?'}@${pkg.package && pkg.package.version || '?'}` });
  }
  // A failing OSV still writes its JSON, so the success path has to carry the
  // reason too.  Reporting ERROR with a null reason leaves the operator with a
  // red result and no explanation of what to fix.
  // osv-scanner uses exit 0 for "nothing found" and exit 1 for "vulnerabilities
  // found", so a clean scan that simply has results must not be reported as a
  // tool failure.  Real tool failures surface at 128 and above.
  const succeeded = osvExitSucceeded(result);
  const failure = succeeded ? null : (result.error || reasonFromStderr(result.stderr) || `OSV exited ${result.status}`);
  return envelope('osv', { status: succeeded ? STATUS.PARTIAL : processStatus(result.state), availability: resolution, version: resolution.version, error: failure, findings, rawArtifact: output, coverage: Object.assign(coverageUnknown(['OSV does not expose a parsed-file denominator']), { analysisCompleted: succeeded, errors: failure ? [`OSV scan failed: ${failure}`] : [] }), cost: { wallClockMs: result.durationMs, timedOut: result.timedOut }, job: standardJob(job, 'osv', result.state, result) });
}

function zizmorInputs(root, files) {
  const usable = [];
  const rejected = [];
  for (const file of files || []) {
    const normalized = String(file || '').replace(/\\/g, '/');
    const absolute = abs(root, normalized);
    if (!absolute) { rejected.push({ file: normalized, reason: 'path is outside the audited repository' }); continue; }
    const containment = realContained(root, absolute);
    if (!containment.ok) { rejected.push({ file: normalized, reason: containment.reason }); continue; }
    try {
      if (!fs.statSync(containment.real).isFile()) { rejected.push({ file: normalized, reason: 'not a regular file' }); continue; }
    } catch (error) { rejected.push({ file: normalized, reason: `unreadable: ${error.code || error.message}` }); continue; }
    usable.push(normalized);
  }
  return { usable: [...new Set(usable)], rejected };
}

async function zizmor(root, ctx, job, opts = {}) {
  const inputs = zizmorInputs(root, opts.ciFiles || []);
  if (!inputs.usable.length && !inputs.rejected.length) {
    return envelope('zizmor', {
      status: STATUS.SKIPPED, notApplicable: true, findings: [], findingCount: 0,
      coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true, coverageKnown: true, coverageUnknown: false, engineCoverage: 'TRACKED_CI_DEFINITIONS', errors: [] },
      notes: ['No tracked workflow, local action, root action.yml, or Dependabot definition was in scope.'],
      job: standardJob(job, 'zizmor', JOB_STATE.SUCCEEDED),
    });
  }
  const resolution = await resolutionFor('zizmor', ctx, job);
  if (!resolution.available) return jobEnvelope('zizmor', resolution, standardJob(job, 'zizmor', JOB_STATE.UNAVAILABLE));
  if (!inputs.usable.length) return envelope('zizmor', {
    status: STATUS.ERROR, availability: resolution, findings: [], findingCount: 0,
    error: 'No tracked CI definition survived path and containment checks.',
    coverage: { filesSeen: (opts.ciFiles || []).length, filesEligible: (opts.ciFiles || []).length, filesParsed: 0, analysisCompleted: false, coverageKnown: false, coverageUnknown: true, engineCoverage: 'TRACKED_CI_DEFINITIONS', errors: inputs.rejected.map((entry) => `${entry.file}: ${entry.reason}`) },
    notes: inputs.rejected, job: standardJob(job, 'zizmor', JOB_STATE.FAILED),
  });

  const args = ['--format=sarif'];
  if (ctx.tools.zizmor.offline !== false) args.push('--offline');
  args.push(...inputs.usable);
  const result = await execute('zizmor', ctx, job, resolution.path, args, 'scan', root);
  if (!result.stdout) return envelope('zizmor', { status: processStatus(result.state), availability: resolution, error: result.error || result.stderr || 'zizmor produced no SARIF', findings: [], findingCount: 0, coverage: coverageUnknown(['missing zizmor SARIF']), cost: { wallClockMs: result.durationMs, timedOut: result.timedOut }, rawArtifact: rawDirectory(ctx, 'zizmor'), job: standardJob(job, 'zizmor', result.state, result), notes: inputs.rejected });
  let parsed;
  try { parsed = JSON.parse(result.stdout); }
  catch (error) { return envelope('zizmor', { status: STATUS.ERROR, availability: resolution, error: `invalid zizmor SARIF: ${error.message}`, findings: [], findingCount: 0, coverage: coverageUnknown(['invalid zizmor SARIF']), cost: { wallClockMs: result.durationMs, timedOut: result.timedOut }, rawArtifact: rawDirectory(ctx, 'zizmor'), job: standardJob(job, 'zizmor', JOB_STATE.FAILED, result), notes: inputs.rejected }); }
  if (!Array.isArray(parsed.runs)) return envelope('zizmor', { status: STATUS.ERROR, availability: resolution, error: 'zizmor output is not a SARIF document', findings: [], findingCount: 0, coverage: coverageUnknown(['invalid zizmor SARIF schema']), cost: { wallClockMs: result.durationMs, timedOut: result.timedOut }, rawArtifact: rawDirectory(ctx, 'zizmor'), job: standardJob(job, 'zizmor', JOB_STATE.FAILED, result), notes: inputs.rejected });
  const output = contained(ctx.work, 'specialists', 'zizmor', 'raw', 'zizmor.sarif');
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, result.stdout, { flag: 'wx' });
  const findings = parseSarif(root, parsed, { tool: 'zizmor', kind: 'ci-cd' });
  const failed = !result.ok;
  const errors = [
    ...(failed ? [result.error || result.stderr || `zizmor exited ${result.status}`] : []),
    ...inputs.rejected.map((entry) => `${entry.file}: ${entry.reason}`),
  ];
  return envelope('zizmor', {
    status: failed ? processStatus(result.state) : STATUS.PARTIAL,
    availability: resolution, version: resolution.version, findings, rawArtifact: output,
    coverage: { filesSeen: (opts.ciFiles || []).length, filesEligible: (opts.ciFiles || []).length, filesParsed: failed ? null : inputs.usable.length, analysisCompleted: !failed, coverageKnown: !failed && !inputs.rejected.length, coverageUnknown: failed || !!inputs.rejected.length, engineCoverage: 'TRACKED_CI_DEFINITIONS', errors },
    cost: { wallClockMs: result.durationMs, timedOut: result.timedOut },
    job: standardJob(job, 'zizmor', failed ? result.state : JOB_STATE.SUCCEEDED, result), notes: inputs.rejected,
  });
}

async function executeSpecialist(tool, root, ctx, job, opts = {}) {
  if (tool === 'codeql') return codeql(root, ctx, job, opts);
  if (tool === 'semgrep') return semgrep(root, ctx, job, opts);
  if (tool === 'trivy') return trivy(root, ctx, job, opts);
  if (tool === 'osv') return osv(root, ctx, job, opts);
  if (tool === 'zizmor') return zizmor(root, ctx, job, opts);
  return jobEnvelope(tool, { name: tool, available: false, state: 'UNAVAILABLE', reason: 'adapter is not implemented for this specialist' }, standardJob(job, tool, JOB_STATE.UNAVAILABLE));
}

module.exports = { executeSpecialist, coverageUnknown, jobEnvelope, parseSarif, sarifArtifact, zizmorInputs, abs, normalizeSemgrepRuleId, localSemgrepConfigs, usableTargets, reasonFromStderr, osvExitSucceeded, OUTCOME, specialistOutcome, processStatus };
