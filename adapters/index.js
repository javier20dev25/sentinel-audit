'use strict';
/**
 * Tool adapters. Each one returns the uniform envelope from lib/core.
 *
 * Contract for every adapter, and the reason this file is not a scanner:
 *   1. Never interpret the tool's output. Report what it said.
 *   2. Always fill coverage. "0 findings" without coverage is a bug.
 *   3. Never exceed the cost budget silently.
 *   4. Never execute anything from the target. No install, no build, no test.
 */
const fs = require('fs');
const path = require('path');
const { STATUS, envelope, run, expand, dirBytes, snippet } = require('../lib/core');
const { writeJson } = require('../workflow/artifacts');
const { redactValue } = require('../workflow/tooling');
const { normalizeCloudSignals, cloudSignalCategory } = require('./normalize');
const { runHostedCloud } = require('./hosted');

const abs = (root, p) => path.resolve(root, String(p || '').replace(/\\/g, '/'));

function scopedFiles(root, targets, accepts) {
  const out = new Set();
  const skip = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build']);
  const visit = (entry, depth = 0) => {
    if (depth > 32) return;
    let st; try { st = fs.statSync(entry); } catch (e) { return; }
    if (st.isFile()) { if (accepts(entry)) out.add(path.resolve(entry)); return; }
    if (!st.isDirectory()) return;
    let ents; try { ents = fs.readdirSync(entry, { withFileTypes: true }); } catch (e) { return; }
    for (const ent of ents) {
      if (ent.isDirectory() && skip.has(ent.name)) continue;
      if (ent.isSymbolicLink()) continue;
      visit(path.join(entry, ent.name), depth + 1);
    }
  };
  for (const target of targets || []) visit(path.resolve(root, target));
  return [...out].sort();
}

/** Direct local adapter for the Sentinel Cloud worker engine. */
function sentinelCloud(root, ctx) {
  return runSentinelCloud(root, ctx, require);
}

function runSentinelCloud(root, ctx, engineLoader = require, enginePathOverride = null) {
  const enginePath = enginePathOverride || (ctx.tools.sentinelCloud && ctx.tools.sentinelCloud.engine ? expand(ctx.tools.sentinelCloud.engine) : null);
  const rawDir = path.join(ctx.work, 'cloud');
  fs.mkdirSync(rawDir, { recursive: true });
  const rawPath = path.join(rawDir, 'raw.json');
  if (!enginePath || (!enginePathOverride && !fs.existsSync(enginePath))) {
    return envelope('sentinel', { status: STATUS.UNSUPPORTED, error: `Sentinel Cloud local engine missing or unconfigured: ${enginePath || 'none'}; use --cloud for hosted provider` });
  }
  const started = Date.now();
  let scan;
  try {
    const engine = engineLoader(enginePath);
    if (typeof engine.scanDirectory !== 'function') throw new Error('scanDirectory export missing');
    scan = engine.scanDirectory(root, null, 5, { mode: 'local', profile: 'DEFAULT' });
  } catch (error) {
    return envelope('sentinel', { status: STATUS.ERROR, cost: { wallClockMs: Date.now() - started }, error: `direct Cloud scan failed: ${error.message}` });
  }
  if (!scan || typeof scan.then !== 'function') {
    return envelope('sentinel', { status: STATUS.ERROR, cost: { wallClockMs: Date.now() - started }, error: 'Cloud scanDirectory did not return a promise' });
  }
  return scan.then((result) => {
    const rawSignals = Array.isArray(result.rawAlerts) ? result.rawAlerts : Array.isArray(result.alerts) ? result.alerts : [];
    const identity = ctx.pre && ctx.pre.health && ctx.pre.health.sentinel || null;
    try {
      // Raw evidence is persisted before normalization and never overwritten.
      // Values are redacted on write so a scanner cannot turn the artifact store
      // into a credential vault; the structure remains the direct engine result.
      writeJson(rawPath, { engine: identity, enginePath, mode: 'local', result: redactValue(result) });
    } catch (error) {
      return envelope('sentinel', { status: STATUS.ERROR, cost: { wallClockMs: Date.now() - started }, error: `raw output persistence failed: ${error.message}` });
    }
    const findings = normalizeCloudSignals(root, rawSignals);
    const actionable = findings.filter((f) => f.signalClass === 'ACTIONABLE_SIGNAL').length;
    const attempted = Number.isInteger(result.filesScanned) ? result.filesScanned : null;
    const filesFailed = Number.isInteger(result.filesScanFailed) ? result.filesScanFailed : null;
    const alertsFailed = Number.isInteger(result.alertsEnrichFailed) ? result.alertsEnrichFailed : null;
    const degradationSamples = Array.isArray(result.degradationSamples) ? result.degradationSamples.length : null;
    return envelope('sentinel', {
      status: STATUS.PARTIAL, findings,
      signalCounts: { total: findings.length, actionable, observationOnly: findings.length - actionable },
      coverage: {
        filesSeen: attempted, filesEligible: null, filesParsed: null,
        parseErrors: null, unsupportedFiles: null, analysisCompleted: true,
        engineExecutionComplete: true, engineIncomplete: false, coverageKnown: false, coverageUnknown: true,
        filesScanned: attempted, filesFailed, alertsSeen: rawSignals.length, alertsEnrichFailed: alertsFailed,
        // Legacy alias preserved for old reports; new code uses alertsEnrichFailed.
        alertsFailed, degradationSamples,
        engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', engineFilesScannedReported: attempted,
        errors: ['Cloud engine does not expose parsed-file or parser-error counters'],
      },
      cost: { wallClockMs: Date.now() - started },
      notes: [
        'direct local Sentinel Cloud worker engine; hosted scan endpoint not used',
        'PRODUCTION_PARITY_UNKNOWN: this result identifies the local source, not the currently deployed worker',
        'raw engine output persisted before normalization',
        'ENGINE_COVERAGE_UNMEASURED: filesScanned is not parsed-file coverage',
      ],
      rawArtifact: rawPath, version: identity && identity.engineId || null,
    });
  }).catch((error) => envelope('sentinel', {
    status: STATUS.ERROR,
    coverage: { engineExecutionComplete: false, engineIncomplete: true, coverageKnown: false, coverageUnknown: true, filesScanned: null, filesFailed: null, alertsSeen: null, alertsEnrichFailed: null, alertsFailed: null, degradationSamples: null, errors: [`direct Cloud scan failed: ${error.message}`] },
    cost: { wallClockMs: Date.now() - started }, error: `direct Cloud scan failed: ${error.message}`,
  }));
}

// ---------------------------------------------------------------- codeql
/** Primary dataflow authority. Needs explicit RAM; a dead run must not read as 0. */
function codeql(root, ctx, opts = {}) {
  const cfg = ctx.tools.codeql;
  if (!fs.existsSync(expand(cfg.bin))) return envelope('codeql', { status: STATUS.UNSUPPORTED, error: 'codeql binary missing' });
  const lang = opts.language || (ctx.inv && ctx.inv.mainLanguage);
  const suite = cfg.suites[lang];
  if (!suite) return envelope('codeql', { status: STATUS.UNSUPPORTED, error: `no query suite for language "${lang}"`, coverage: { filesSeen: null, filesEligible: null, filesParsed: null, scopeFilesRequested: ctx.inv.sourceFiles, analysisCompleted: false, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED' } });
  if (!fs.existsSync(expand(suite))) return envelope('codeql', { status: STATUS.ERROR, error: `query suite missing: ${suite}`, notes: ['run: codeql pack download'] });

  const db = path.join(ctx.work, 'codeql-db');
  const sarif = path.join(ctx.work, 'specialists', 'codeql', 'raw', 'codeql.sarif');
  fs.mkdirSync(path.dirname(sarif), { recursive: true });
  const ram = opts.ram || ctx.policies.budget.codeqlDefaultRam;
  let cost = { wallClockMs: 0, timedOut: false, peakRamMB: null, ramBudgetMB: ram, dbBytes: null, artifactBytes: null, overBudget: false };

  // A stale database is worse than no database: CodeQL happily analyzes whatever
  // is on disk, and --overwrite does not clear the previous run's log directory,
  // so stale results look fresh. Start from nothing unless the caller wants to keep it.
  if (fs.existsSync(db) && !ctx.keepDb) {
    try { fs.rmSync(db, { recursive: true, force: true }); } catch (e) { /* best effort */ }
  }

  const create = run(expand(cfg.bin), ['database', 'create', '--language=' + lang, '--overwrite',
    '--ram=' + ram, '--source-root=' + root, '--', db], { timeoutMs: ctx.budget('codeql') });
  cost.wallClockMs += create.cost.wallClockMs;
  const codeqlRawDir = path.join(ctx.work, 'specialists', 'codeql', 'raw');
  fs.writeFileSync(path.join(codeqlRawDir, 'database-create.json'), JSON.stringify({ status: create.status, signal: create.signal, error: create.error, timedOut: create.cost.timedOut, stderr: create.stderr }, null, 2), { flag: 'wx' });
  if (!fs.existsSync(db)) {
    return envelope('codeql', { status: STATUS.ERROR, cost, error: 'database create failed', notes: [String(create.stderr).slice(0, 400)] });
  }
  cost.dbBytes = dirBytes(db);
  const finalize = run(expand(cfg.bin), ['database', 'finalize', '--ram=' + ram, db], { timeoutMs: ctx.budget('codeql') });
  cost.wallClockMs += finalize.cost.wallClockMs;
  fs.writeFileSync(path.join(codeqlRawDir, 'database-finalize.json'), JSON.stringify({ status: finalize.status, signal: finalize.signal, error: finalize.error, timedOut: finalize.cost.timedOut, stderr: finalize.stderr }, null, 2), { flag: 'wx' });
  if (!finalize.ok || finalize.cost.timedOut) {
    return envelope('codeql', { status: STATUS.ERROR, cost: { ...cost, timedOut: finalize.cost.timedOut }, error: 'database finalize failed', notes: [String(finalize.stderr).slice(0, 500)] });
  }
  const an = run(expand(cfg.bin), ['database', 'analyze', '--ram=' + ram, '--format=sarif-latest',
    '--output=' + sarif, '--no-print-diagnostics-summary', '--', db, expand(suite)], { timeoutMs: ctx.budget('codeql') });
  cost.wallClockMs += an.cost.wallClockMs;
  cost.timedOut = cost.timedOut || an.cost.timedOut;
  cost.artifactBytes = fs.existsSync(sarif) ? fs.statSync(sarif).size : null;
  fs.writeFileSync(path.join(codeqlRawDir, 'analyze.json'), JSON.stringify({ status: an.status, signal: an.signal, error: an.error, timedOut: an.cost.timedOut, stderr: an.stderr }, null, 2), { flag: 'wx' });

  // Gate A in practice: absence of SARIF is an ERROR, never zero findings.
  if (!fs.existsSync(sarif)) {
    return envelope('codeql', {
      status: STATUS.ERROR, cost, error: 'analyze produced no SARIF (tool error, NOT zero findings)',
      coverage: { filesSeen: null, filesEligible: null, filesParsed: null, scopeFilesRequested: ctx.inv.sourceFiles, analysisCompleted: false, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: [String(an.stderr).slice(0, 300)] },
      notes: ['raise --ram; the default heap (~914MB) can die mid-run on monorepos'],
    });
  }
  let j;
  try { j = JSON.parse(fs.readFileSync(sarif, 'utf8')); }
  catch (error) { return envelope('codeql', { status: STATUS.ERROR, cost, rawArtifact: sarif, error: `invalid CodeQL SARIF JSON: ${error.message}` }); }
  const out = [];
  for (const run_ of j.runs || []) for (const res of run_.results || []) {
    const L = ((res.locations || [])[0] || {}).physicalLocation || {};
    const f = abs(root, L.artifactLocation && L.artifactLocation.uri);
    const line = L.region && L.region.startLine;
    out.push({
      tool: 'codeql', kind: 'dataflow', rule: res.ruleId, level: res.level,
      file: f, line,
      snippet: snippet(root, f, line),
      // A CodeQL path is only meaningful as source -> ... -> sink; keep the
      // pieces so a reviewer never has to re-open the SARIF to judge reachability.
      path: Array.isArray(res.codeFlows) && res.codeFlows[0] && res.codeFlows[0].threadFlows
        ? res.codeFlows[0].threadFlows[0].locations.map((l) => ({
            file: abs(root, l.location && l.location.physicalLocation && l.location.physicalLocation.artifactLocation && l.location.physicalLocation.artifactLocation.uri),
            line: l.location && l.location.physicalLocation && l.location.physicalLocation.region && l.location.physicalLocation.region.startLine,
            message: String((l.location && l.location.message && l.location.message.text) || '').split('\n')[0].slice(0, 120),
          }))
        : null,
      detail: String((res.message && res.message.text) || '').split('\n')[0].slice(0, 200),
    });
  }
  // The SARIF is the evidence; the database is a build artifact that measured
  // 180MB for a 2000-file repo (126MB of it query logs). Keep one, drop the other.
  const dbBytes = cost.dbBytes;
  let cleanupError = null;
  if (!ctx.keepDb) {
    try { fs.rmSync(db, { recursive: true, force: true }); cost.dbBytes = 0; cost.dbDiscardedBytes = dbBytes; }
    catch (e) { cleanupError = String(e.message || e); }
  }
  return envelope('codeql', {
    status: !an.ok || an.cost.timedOut ? STATUS.PARTIAL : undefined,
    status: cleanupError ? STATUS.PARTIAL : undefined,
    findings: out, cost, rawArtifact: sarif,
    coverage: { filesSeen: null, filesEligible: null, filesParsed: null, scopeFilesRequested: ctx.inv.sourceFiles, analysisCompleted: true, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: ['CodeQL SARIF does not expose parsed source-file totals'] },
    cleanupError,
    notes: ctx.keepDb ? ['database retained (--keep-db)'] : cleanupError
      ? [`CodeQL database cleanup failed: ${cleanupError}`]
      : [`database discarded after SARIF extraction (${Math.round((dbBytes || 0) / 1048576)}MB)`],
  });
}

// ---------------------------------------------------------------- semgrep
function semgrep(root, ctx, opts = {}) {
  if (!/^semgrep$/i.test(ctx.tools.semgrep.bin)) return envelope('semgrep', { status: STATUS.UNSUPPORTED, error: 'semgrep not on PATH' });
  const scopes = opts.scope && opts.scope.length ? opts.scope : [root];
  const configs = ctx.tools.semgrep.configs;
  const targets = Number.isInteger(opts.maxTargets) && opts.maxTargets > 0 ? scopes.slice(0, opts.maxTargets) : scopes;
  const findings = [];
  let cost = { wallClockMs: 0, timedOut: false };
  let errors = 0;
  // One process per CONFIG, with every scope file as an argument. Spawning
  // per-file turns a 2 minute estimate into an hour: 40 files x 3 configs = 120
  // semgrep startups, each paying config resolution.
  for (const cfgName of configs) {
    const rawDir = path.join(ctx.work, 'specialists', 'semgrep', 'raw');
    fs.mkdirSync(rawDir, { recursive: true });
    const r = run('semgrep', ['scan', '--config', cfgName, '--json', '--quiet', '--metrics=off',
      '--disable-version-check', '--no-git-ignore', '--timeout', String(Math.floor(ctx.budget('semgrep') / 1000)),
      '--exclude', 'node_modules', '--exclude', '.git', '--', ...targets],
      { timeoutMs: ctx.budget('semgrep'), cwd: root });
    cost.wallClockMs += r.cost.wallClockMs;
    const rawName = cfgName.replace(/[^a-z0-9._-]+/gi, '_') + '.stdout';
    fs.writeFileSync(path.join(rawDir, rawName), r.stdout || '', { flag: 'wx' });
    fs.writeFileSync(path.join(rawDir, cfgName.replace(/[^a-z0-9._-]+/gi, '_') + '.stderr'), r.stderr || '', { flag: 'wx' });
    fs.writeFileSync(path.join(rawDir, cfgName.replace(/[^a-z0-9._-]+/gi, '_') + '.status.json'), JSON.stringify({ status: r.status, signal: r.signal, error: r.error, timedOut: r.cost.timedOut }, null, 2), { flag: 'wx' });
    if (!r.ok || r.cost.timedOut) errors++;
    const i = String(r.stdout).search(/[[{]/);
    if (i < 0) { errors++; continue; }
    let j = null; try { j = JSON.parse(String(r.stdout).slice(i)); } catch (e) { errors++; continue; }
    errors += (j.errors || []).length;
    for (const x of j.results || []) {
      const f = abs(root, x.path);
      const line = x.start && x.start.line;
      findings.push({
        tool: 'semgrep', kind: 'pattern', rule: x.check_id, level: x.extra && x.extra.severity || null,
        file: f, line, snippet: snippet(root, f, line),
        detail: String((x.extra && x.extra.message) || '').split('\n')[0].slice(0, 200),
      });
    }
  }
  const normalizedPath = path.join(ctx.work, 'specialists', 'semgrep', 'normalized.json');
  fs.mkdirSync(path.dirname(normalizedPath), { recursive: true });
  fs.writeFileSync(normalizedPath, JSON.stringify(findings, null, 2), { flag: 'wx' });
  return envelope('semgrep', {
    findings, cost,
    coverage: { filesSeen: null, filesEligible: null, filesParsed: null, targetsRequested: scopes.length, filesTargeted: targets.length, targetsOmittedByLimit: scopes.length - targets.length, parseErrors: errors, analysisCompleted: true, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: errors ? [`${errors} parser/scan errors`] : ['Semgrep output did not provide a trustworthy scanned-path set'] },
    rawArtifact: path.dirname(normalizedPath),
    notes: errors ? [`${errors} semgrep parse/scan error(s); coverage is partial`] : [],
  });
}

// ---------------------------------------------------------------- bandit
/** Python sink-side. THE parse-error rule lives here. */
function bandit(root, ctx, opts = {}) {
  const bin = expand(ctx.tools.bandit.bin);
  if (!fs.existsSync(bin)) return envelope('bandit', { status: STATUS.UNSUPPORTED, error: 'bandit binary missing' });
  if (!(ctx.inv.byLang.python || 0)) return envelope('bandit', { status: STATUS.SKIPPED, notApplicable: true, notes: ['no python source in target: bandit not applicable'], coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  // Bandit is the noisiest lens in the set: `-r root` over a mature Python repo
  // reports tens of thousands of low-severity items, which buries the promoted
  // signals instead of testing them. Scope it to the promoted files so the
  // count means something, and keep only Python: handing a language-specific
  // tool a file it cannot parse yields a parse error that reads like coverage.
  const langOk = (f) => /\.(py|pyi)$/i.test(f);
  const promoted = scopedFiles(root, opts.scope && opts.scope.length ? opts.scope : [root], langOk);
  if (!promoted.length) {
    return envelope('bandit', { status: STATUS.SKIPPED, notApplicable: true, notes: ['no promoted python file: bandit has nothing to verify in Etapa B'], coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  }
  const scopes = Number.isInteger(opts.maxTargets) && opts.maxTargets > 0 ? promoted.slice(0, opts.maxTargets) : promoted;
  const out = path.join(ctx.work, 'specialists', 'bandit', 'raw', 'bandit.json');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  const r = run(bin, ['-f', 'json', '-o', out, '-q', ...scopes], { timeoutMs: ctx.budget('bandit') });
  if (!fs.existsSync(out)) return envelope('bandit', { status: STATUS.ERROR, cost: r.cost, error: 'bandit produced no output' });
  let j;
  try { j = JSON.parse(fs.readFileSync(out, 'utf8')); }
  catch (error) { return envelope('bandit', { status: STATUS.ERROR, cost: r.cost, rawArtifact: out, error: `invalid Bandit JSON: ${error.message}` }); }
  const results = j.results || [];
  const errs = j.errors || [];
  const status = errs.length ? STATUS.PARTIAL : STATUS.SUCCESS;
  return envelope('bandit', {
    status: status === STATUS.PARTIAL || !r.ok ? STATUS.PARTIAL : undefined,
    findings: results.map((x) => {
      const f = abs(root, x.filename);
      const line = x.line_number;
      return {
        tool: 'bandit', kind: 'python_sink', rule: x.test_id, level: x.issue_severity,
        file: f, line, snippet: snippet(root, f, line),
        detail: `${String(x.issue_text).slice(0, 180)} (confidence ${x.issue_confidence})`,
      };
    }),
    cost: r.cost, rawArtifact: out,
    coverage: {
      filesSeen: null, filesEligible: null, filesParsed: null, filesTargeted: scopes.length,
      coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED',
      parseErrors: errs.length, parseErrorFiles: errs.map((e) => path.basename(String(e.filename))),
      analysisCompleted: true,
    },
    notes: errs.length
      ? [`PARSE FAILURES: ${errs.length} file(s) skipped (e.g. Python 2 syntax). Zero findings here is NOT clean.`]
      : [],
  });
}

// ---------------------------------------------------------------- shellcheck
/** Lint only. Explicitly not a taint detector. */
function shellcheck(root, ctx, opts = {}) {
  const bin = expand(ctx.tools.shellcheck.bin);
  if (!fs.existsSync(bin)) return envelope('shellcheck', { status: STATUS.UNSUPPORTED, error: 'shellcheck binary missing' });
  if (!(ctx.inv.byLang.shell || 0)) return envelope('shellcheck', { status: STATUS.SKIPPED, notApplicable: true, notes: ['no shell source in target: shellcheck not applicable'], coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  const files = [];
  const walk = (d, depth) => {
    if (depth > 12) return;
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
    for (const e of ents) {
      if (['node_modules', '.git', 'vendor', 'dist', 'build'].includes(e.name)) continue;
      const f = path.join(d, e.name);
      if (e.isDirectory()) walk(f, depth + 1);
      else if (/\.(sh|bash)$/.test(e.name) || e.name === 'Dockerfile') files.push(f);
    }
  };
  walk(root, 0);
  // Restrict to promoted files. Lint findings on unreviewed shell scripts are
  // breadth, not deep verification, and on a repo that merely ships a Dockerfile
  // they arrive in the dozens while saying nothing about the promoted signal.
  // Targets arrive as repository-relative identities, so they must be anchored to
  // the audited root.  path.resolve(s) alone would anchor them to the process cwd
  // and match no walked file, which reads as "nothing to check" rather than as a
  // routing error.
  const scope = opts.scope && opts.scope.length ? new Set(opts.scope.map((s) => abs(root, s))) : null;
  const eligible = scope ? files.filter((f) => [...scope].some((s) => path.resolve(f) === s || path.resolve(f).startsWith(s + path.sep))) : files;
  const scoped = Number.isInteger(opts.maxTargets) && opts.maxTargets > 0 ? eligible.slice(0, opts.maxTargets) : eligible;
  if (!scoped.length) {
    return envelope('shellcheck', { status: STATUS.SKIPPED, notApplicable: true, notes: ['no promoted shell file: shellcheck has nothing to verify in Etapa B'], coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  }
  const findings = [];
  let cost = { wallClockMs: 0, timedOut: false };
  let errors = 0;
  const rawDir = path.join(ctx.work, 'specialists', 'shellcheck', 'raw');
  fs.mkdirSync(rawDir, { recursive: true });
  const CHUNK = 20;
  for (let i = 0; i < scoped.length; i += CHUNK) {
    const batch = scoped.slice(i, i + CHUNK);
    const r = run(bin, ['-f', 'json', '-S', ctx.tools.shellcheck.severity, ...batch], { timeoutMs: 120000 });
    cost.wallClockMs += r.cost.wallClockMs;
    const prefix = path.join(rawDir, `batch-${Math.floor(i / CHUNK)}`);
    fs.writeFileSync(prefix + '.stdout', r.stdout || '', { flag: 'wx' });
    fs.writeFileSync(prefix + '.stderr', r.stderr || '', { flag: 'wx' });
    fs.writeFileSync(prefix + '.status.json', JSON.stringify({ status: r.status, signal: r.signal, error: r.error, timedOut: r.cost.timedOut }, null, 2), { flag: 'wx' });
    if ((r.status != null && r.status > 1) || r.error || r.cost.timedOut) errors++;
    let parsed = null;
    try { parsed = JSON.parse(r.stdout || '[]'); } catch (e) { errors++; }
    for (const c of (parsed || [])) findings.push({ tool: 'shellcheck', kind: 'lint', rule: 'SC' + c.code, file: (c.file || '').trim(), line: c.line, detail: String(c.message).slice(0, 180) });
  }
  return envelope('shellcheck', {
    status: errors ? STATUS.PARTIAL : undefined,
    findings, cost,
    coverage: { filesSeen: null, filesEligible: null, filesParsed: null, filesTargeted: scoped.length, parseErrors: errors, analysisCompleted: true, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: errors ? [`${errors} shellcheck batch error(s)`] : ['ShellCheck output does not attest a complete parsed-file denominator'] },
    rawArtifact: rawDir,
    notes: ['LINT ONLY - ShellCheck is not a taint detector; a clean run says nothing about injection'],
  });
}

// ---------------------------------------------------------------- trivy
function trivy(root, ctx) {
  const bin = expand(ctx.tools.trivy.bin);
  if (!fs.existsSync(bin)) return envelope('trivy', { status: STATUS.UNSUPPORTED, error: 'trivy binary missing' });
  const out = path.join(ctx.work, 'specialists', 'trivy', 'raw', 'trivy.json');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  const r = run(bin, ['fs', '--format', 'json', '--output', out, '--scanners', ctx.tools.trivy.scanners,
    '--skip-dirs', 'node_modules,.git', '--quiet', root], { timeoutMs: ctx.budget('trivy') });
  if (!fs.existsSync(out)) return envelope('trivy', { status: STATUS.ERROR, cost: r.cost, error: 'trivy produced no output', notes: [String(r.stderr).slice(0, 200)] });
  let j;
  try { j = JSON.parse(fs.readFileSync(out, 'utf8')); }
  catch (error) { return envelope('trivy', { status: STATUS.ERROR, cost: r.cost, rawArtifact: out, error: `invalid Trivy JSON: ${error.message}` }); }
  const findings = [];
  for (const res of j.Results || []) {
    for (const v of res.Vulnerabilities || []) findings.push({ tool: 'trivy', kind: 'sca', rule: v.VulnerabilityID, level: v.Severity, file: abs(root, res.Target), detail: `${v.PkgName}@${v.InstalledVersion}${v.FixedVersion ? ' fixed in ' + v.FixedVersion : ' (no fix)'}`, pkg: v.PkgName, fixed: v.FixedVersion || null });
    for (const m of res.Misconfigurations || []) findings.push({ tool: 'trivy', kind: 'misconfig', rule: m.ID, level: m.Severity, file: abs(root, res.Target), detail: m.Title });
    for (const s of res.Secrets || []) findings.push({ tool: 'trivy', kind: 'secret', rule: s.RuleID, level: s.Severity, file: abs(root, s.Target), line: s.StartLine, detail: 'secret detected (value never recorded)', secret: true });
  }
  return envelope('trivy', { findings, cost: r.cost, rawArtifact: out, coverage: { filesSeen: null, filesEligible: null, filesParsed: null, analysisCompleted: true, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: ['Trivy JSON does not provide a verified parsed-file denominator'] } });
}

// ---------------------------------------------------------------- osv
function osv(root, ctx) {
  const bin = expand(ctx.tools.osv.bin);
  if (!fs.existsSync(bin)) return envelope('osv', { status: STATUS.UNSUPPORTED, error: 'osv-scanner binary missing' });
  if (!ctx.inv.lockfiles.length) {
    return envelope('osv', { status: STATUS.SKIPPED, notes: ['no lockfile: SCA impossible, which is a COVERAGE GAP and not a clean result'], coverage: { filesSeen: ctx.inv.totalFiles, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  }
  const out = path.join(ctx.work, 'specialists', 'osv', 'raw', 'osv.json');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  const r = run(bin, ['scan', 'source', '--format', 'json', '--output', out, root], { timeoutMs: ctx.budget('osv') });
  if (!fs.existsSync(out)) return envelope('osv', { status: STATUS.ERROR, cost: r.cost, error: 'osv produced no output', notes: [String(r.stderr).slice(0, 200)] });
  let j;
  try { j = JSON.parse(fs.readFileSync(out, 'utf8')); }
  catch (error) { return envelope('osv', { status: STATUS.ERROR, cost: r.cost, rawArtifact: out, error: `invalid OSV JSON: ${error.message}` }); }
  const findings = [];
  for (const res of j.results || []) for (const pkg of res.packages || []) for (const v of pkg.vulnerabilities || []) {
    findings.push({ tool: 'osv', kind: 'sca', rule: v.id, level: (v.severity || []).map((s) => s.score).join(','), file: path.join(root, 'package.json'), detail: `${(pkg.package && (pkg.package.name || pkg.package.source)) || '?'}@${(pkg.package && pkg.package.version) || '?'}`, pkg: (pkg.package && pkg.package.name) || null });
  }
  return envelope('osv', { findings, cost: r.cost, rawArtifact: out, coverage: { filesSeen: null, filesEligible: null, filesParsed: null, analysisCompleted: true, coverageKnown: false, coverageUnknown: true, engineCoverage: 'ENGINE_COVERAGE_UNMEASURED', errors: ['OSV source scan does not provide a verified parsed source-file denominator'] } });
}

module.exports = { sentinel: sentinelCloud, hosted: runHostedCloud, runSentinelCloud, runHostedCloud, normalizeCloudSignals, cloudSignalCategory, codeql, semgrep, bandit, shellcheck, trivy, osv };
