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

const abs = (root, p) => path.resolve(root, String(p || '').replace(/\\/g, '/'));

function cloudSignalCategory(signal) {
  const raw = JSON.stringify(signal).toLowerCase();
  const type = String(signal.type || signal.rule || '').toLowerCase();
  if (/secret|credential|token/.test(type)) return 'secret';
  if (/dependency|lockfile|sca|typosquat|vulnerable_dep/.test(type)) return 'dependency';
  if (/lifecycle|install_hook|postinstall/.test(type)) return 'lifecycle';
  if (/network|http|fetch|socket|exfil/.test(type) || /"intent":"(network|exfiltration)"/.test(raw)) return 'network';
  if (/filesystem|file_write|fs_write|write_file|persistence/.test(type)) return 'filesystem';
  if (/process|command|shell|exec|dynamic_execution|unsafe_eval/.test(type) || /"intent":"execution"/.test(raw)) return 'process';
  if (/capability_chain/.test(type)) {
    if (/execution|exec|process|shell/.test(raw)) return 'process';
    if (/network|fetch|http|exfil/.test(raw)) return 'network';
    if (/filesystem|file_write|write/.test(raw)) return 'filesystem';
  }
  return 'observation';
}

function normalizeCloudSignals(root, rawSignals) {
  return rawSignals.map((signal) => {
    const candidate = signal._fullPath || signal.file || signal._file || signal.filename || null;
    const file = candidate ? path.resolve(root, candidate) : null;
    const rel = file ? path.relative(root, file) : '';
    const insideRoot = !!file && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
    const category = cloudSignalCategory(signal);
    const evidence = signal.evidence;
    const detail = [signal.title, signal.description, signal.message, signal.snippet,
      Array.isArray(evidence) ? evidence.join(' → ') : evidence]
      .filter((part) => typeof part === 'string' && part.trim()).join(' | ');
    return {
      tool: 'sentinel', rule: signal.type || signal.ruleName || 'cloud_signal',
      kind: signal.type || 'observation', category, file: insideRoot ? file : null,
      line: Number.isInteger(signal.line) ? signal.line : Number.isInteger(signal.line_number) ? signal.line_number : null,
      detail,
      signalClass: category !== 'observation' && insideRoot && !!detail ? 'ACTIONABLE_SIGNAL' : 'OBSERVATION_ONLY',
      rawEngineSignal: signal,
    };
  });
}

/** Direct local adapter for the Sentinel Cloud worker engine. */
function sentinelCloud(root, ctx) {
  const enginePath = expand(ctx.tools.sentinelCloud.engine);
  const rawPath = path.join(ctx.work, 'sentinel.json');
  if (!fs.existsSync(enginePath)) return envelope('sentinel', { status: STATUS.UNSUPPORTED, error: `Sentinel Cloud engine missing: ${enginePath}` });
  const started = Date.now();
  let scan;
  try {
    const engine = require(enginePath);
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
      fs.writeFileSync(rawPath, JSON.stringify({ engine: identity, enginePath, mode: 'local', result }, null, 2));
    } catch (error) {
      return envelope('sentinel', { status: STATUS.ERROR, cost: { wallClockMs: Date.now() - started }, error: `raw output persistence failed: ${error.message}` });
    }
    const findings = normalizeCloudSignals(root, rawSignals);
    const actionable = findings.filter((f) => f.signalClass === 'ACTIONABLE_SIGNAL').length;
    const attempted = Number.isInteger(result.filesScanned) ? result.filesScanned : null;
    return envelope('sentinel', {
      status: STATUS.PARTIAL, findings,
      signalCounts: { total: findings.length, actionable, observationOnly: findings.length - actionable },
      coverage: {
        filesSeen: attempted, filesEligible: null, filesParsed: null,
        parseErrors: null, unsupportedFiles: null, analysisCompleted: false,
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
    status: STATUS.ERROR, cost: { wallClockMs: Date.now() - started }, error: `direct Cloud scan failed: ${error.message}`,
  }));
}

// ---------------------------------------------------------------- codeql
/** Primary dataflow authority. Needs explicit RAM; a dead run must not read as 0. */
function codeql(root, ctx, opts = {}) {
  const cfg = ctx.tools.codeql;
  if (!fs.existsSync(expand(cfg.bin))) return envelope('codeql', { status: STATUS.UNSUPPORTED, error: 'codeql binary missing' });
  const lang = opts.language || (ctx.inv && ctx.inv.mainLanguage);
  const suite = cfg.suites[lang];
  if (!suite) return envelope('codeql', { status: STATUS.UNSUPPORTED, error: `no query suite for language "${lang}"`, coverage: { filesSeen: ctx.inv.sourceFiles, filesEligible: ctx.inv.sourceFiles, analysisCompleted: false } });
  if (!fs.existsSync(expand(suite))) return envelope('codeql', { status: STATUS.ERROR, error: `query suite missing: ${suite}`, notes: ['run: codeql pack download'] });

  const db = path.join(ctx.work, 'codeql-db');
  const sarif = path.join(ctx.work, 'codeql.sarif');
  const ram = opts.ram || ctx.policies.budget.codeqlDefaultRam;
  let cost = { wallClockMs: 0, timedOut: false, peakRamMB: ram, dbBytes: null, artifactBytes: null, overBudget: false };

  // A stale database is worse than no database: CodeQL happily analyzes whatever
  // is on disk, and --overwrite does not clear the previous run's log directory,
  // so stale results look fresh. Start from nothing unless the caller wants to keep it.
  if (fs.existsSync(db) && !ctx.keepDb) {
    try { fs.rmSync(db, { recursive: true, force: true }); } catch (e) { /* best effort */ }
  }

  const create = run(expand(cfg.bin), ['database', 'create', '--language=' + lang, '--overwrite',
    '--ram=' + ram, '--source-root=' + root, '--', db], { timeoutMs: ctx.budget('codeql') });
  cost.wallClockMs += create.cost.wallClockMs;
  if (!fs.existsSync(db)) {
    return envelope('codeql', { status: STATUS.ERROR, cost, error: 'database create failed', notes: [String(create.stderr).slice(0, 400)] });
  }
  cost.dbBytes = dirBytes(db);
  run(expand(cfg.bin), ['database', 'finalize', '--ram=' + ram, db], { timeoutMs: ctx.budget('codeql') });
  const an = run(expand(cfg.bin), ['database', 'analyze', '--ram=' + ram, '--format=sarif-latest',
    '--output=' + sarif, '--no-print-diagnostics-summary', '--', db, expand(suite)], { timeoutMs: ctx.budget('codeql') });
  cost.wallClockMs += an.cost.wallClockMs;
  cost.timedOut = cost.timedOut || an.cost.timedOut;
  cost.artifactBytes = fs.existsSync(sarif) ? fs.statSync(sarif).size : null;

  // Gate A in practice: absence of SARIF is an ERROR, never zero findings.
  if (!fs.existsSync(sarif)) {
    return envelope('codeql', {
      status: STATUS.ERROR, cost, error: 'analyze produced no SARIF (tool error, NOT zero findings)',
      coverage: { filesSeen: ctx.inv.sourceFiles, filesEligible: ctx.inv.sourceFiles, filesParsed: 0, analysisCompleted: false, errors: [String(an.stderr).slice(0, 300)] },
      notes: ['raise --ram; the default heap (~914MB) can die mid-run on monorepos'],
    });
  }
  const j = JSON.parse(fs.readFileSync(sarif, 'utf8'));
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
  if (!ctx.keepDb) {
    try { fs.rmSync(db, { recursive: true, force: true }); cost.dbBytes = 0; cost.dbDiscardedBytes = dbBytes; } catch (e) { /* keep evidence, note the failure */ }
  }
  return envelope('codeql', {
    findings: out, cost, rawArtifact: sarif,
    coverage: { filesSeen: ctx.inv.sourceFiles, filesEligible: ctx.inv.sourceFiles, filesParsed: ctx.inv.sourceFiles, analysisCompleted: true },
    notes: ctx.keepDb ? ['database retained (--keep-db)'] : [`database discarded after SARIF extraction (${Math.round((dbBytes || 0) / 1048576)}MB)`],
  });
}

// ---------------------------------------------------------------- semgrep
function semgrep(root, ctx, opts = {}) {
  if (!/^semgrep$/i.test(ctx.tools.semgrep.bin)) return envelope('semgrep', { status: STATUS.UNSUPPORTED, error: 'semgrep not on PATH' });
  const scopes = opts.scope && opts.scope.length ? opts.scope : [root];
  const configs = ctx.tools.semgrep.configs;
  const targets = scopes.slice(0, opts.maxTargets || 25);
  const findings = [];
  let cost = { wallClockMs: 0, timedOut: false };
  let errors = 0;
  // One process per CONFIG, with every scope file as an argument. Spawning
  // per-file turns a 2 minute estimate into an hour: 40 files x 3 configs = 120
  // semgrep startups, each paying config resolution.
  for (const cfgName of configs) {
    const r = run('semgrep', ['scan', '--config', cfgName, '--json', '--quiet', '--metrics=off',
      '--disable-version-check', '--no-git-ignore', '--timeout', String(Math.floor(ctx.budget('semgrep') / 1000)),
      '--exclude', 'node_modules', '--exclude', '.git', '--', ...targets],
      { timeoutMs: ctx.budget('semgrep'), cwd: root });
    cost.wallClockMs += r.cost.wallClockMs;
    const i = String(r.stdout).search(/[[{]/);
    if (i < 0) { errors++; continue; }
    let j = null; try { j = JSON.parse(String(r.stdout).slice(i)); } catch (e) { errors++; continue; }
    errors += (j.errors || []).length;
    for (const x of j.results || []) {
      const f = abs(root, x.path);
      const line = x.start && x.start.line;
      findings.push({
        tool: 'semgrep', kind: 'pattern', rule: x.check_id,
        file: f, line, snippet: snippet(root, f, line),
        detail: String((x.extra && x.extra.message) || '').split('\n')[0].slice(0, 200),
      });
    }
  }
  return envelope('semgrep', {
    findings, cost,
    coverage: { filesSeen: ctx.inv.sourceFiles, filesEligible: ctx.inv.sourceFiles, filesParsed: ctx.inv.sourceFiles, parseErrors: errors, analysisCompleted: true },
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
  const promoted = (opts.scope && opts.scope.length ? opts.scope : [root]).filter(langOk);
  if (!promoted.length) {
    return envelope('bandit', { status: STATUS.SKIPPED, notApplicable: true, notes: ['no promoted python file: bandit has nothing to verify in Etapa B'], coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  }
  const scopes = promoted.slice(0, opts.maxTargets || 50);
  const out = path.join(ctx.work, 'bandit.json');
  const r = run(bin, ['-f', 'json', '-o', out, '-q', ...scopes], { timeoutMs: ctx.budget('bandit') });
  if (!fs.existsSync(out)) return envelope('bandit', { status: STATUS.ERROR, cost: r.cost, error: 'bandit produced no output' });
  const j = JSON.parse(fs.readFileSync(out, 'utf8'));
  const results = j.results || [];
  const errs = j.errors || [];
  const status = errs.length ? STATUS.PARTIAL : STATUS.SUCCESS;
  return envelope('bandit', {
    status,
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
      filesSeen: ctx.inv.byLang.python, filesEligible: ctx.inv.byLang.python,
      filesParsed: ctx.inv.byLang.python - new Set(errs.map((e) => e.filename)).size,
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
  const scope = opts.scope && opts.scope.length ? new Set(opts.scope.map((s) => path.resolve(s))) : null;
  const scoped = (scope ? files.filter((f) => scope.has(path.resolve(f))) : files).slice(0, opts.maxTargets || 50);
  if (!scoped.length) {
    return envelope('shellcheck', { status: STATUS.SKIPPED, notApplicable: true, notes: ['no promoted shell file: shellcheck has nothing to verify in Etapa B'], coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  }
  const findings = [];
  let cost = { wallClockMs: 0, timedOut: false };
  const CHUNK = 20;
  for (let i = 0; i < scoped.length; i += CHUNK) {
    const batch = scoped.slice(i, i + CHUNK);
    const r = run(bin, ['-f', 'json', '-S', ctx.tools.shellcheck.severity, ...batch], { timeoutMs: 120000 });
    cost.wallClockMs += r.cost.wallClockMs;
    let parsed = null;
    try { parsed = JSON.parse(r.stdout || '[]'); } catch (e) { /* non-JSON on hard syntax errors */ }
    for (const c of (parsed || [])) findings.push({ tool: 'shellcheck', kind: 'lint', rule: 'SC' + c.code, file: (c.file || '').trim(), line: c.line, detail: String(c.message).slice(0, 180) });
  }
  return envelope('shellcheck', {
    findings, cost,
    coverage: { filesSeen: files.length, filesEligible: files.length, filesParsed: files.length, analysisCompleted: true },
    notes: ['LINT ONLY - ShellCheck is not a taint detector; a clean run says nothing about injection'],
  });
}

// ---------------------------------------------------------------- trivy
function trivy(root, ctx) {
  const bin = expand(ctx.tools.trivy.bin);
  if (!fs.existsSync(bin)) return envelope('trivy', { status: STATUS.UNSUPPORTED, error: 'trivy binary missing' });
  const out = path.join(ctx.work, 'trivy.json');
  const r = run(bin, ['fs', '--format', 'json', '--output', out, '--scanners', ctx.tools.trivy.scanners,
    '--skip-dirs', 'node_modules,.git', '--quiet', root], { timeoutMs: ctx.budget('trivy') });
  if (!fs.existsSync(out)) return envelope('trivy', { status: STATUS.ERROR, cost: r.cost, error: 'trivy produced no output', notes: [String(r.stderr).slice(0, 200)] });
  const j = JSON.parse(fs.readFileSync(out, 'utf8'));
  const findings = [];
  for (const res of j.Results || []) {
    for (const v of res.Vulnerabilities || []) findings.push({ tool: 'trivy', kind: 'sca', rule: v.VulnerabilityID, level: v.Severity, file: abs(root, res.Target), detail: `${v.PkgName}@${v.InstalledVersion}${v.FixedVersion ? ' fixed in ' + v.FixedVersion : ' (no fix)'}`, pkg: v.PkgName, fixed: v.FixedVersion || null });
    for (const m of res.Misconfigurations || []) findings.push({ tool: 'trivy', kind: 'misconfig', rule: m.ID, level: m.Severity, file: abs(root, res.Target), detail: m.Title });
    for (const s of res.Secrets || []) findings.push({ tool: 'trivy', kind: 'secret', rule: s.RuleID, level: s.Severity, file: abs(root, s.Target), line: s.StartLine, detail: 'secret detected (value never recorded)', secret: true });
  }
  return envelope('trivy', { findings, cost: r.cost, rawArtifact: out, coverage: { filesSeen: ctx.inv.totalFiles, filesEligible: ctx.inv.totalFiles, filesParsed: ctx.inv.totalFiles, analysisCompleted: true } });
}

// ---------------------------------------------------------------- osv
function osv(root, ctx) {
  const bin = expand(ctx.tools.osv.bin);
  if (!fs.existsSync(bin)) return envelope('osv', { status: STATUS.UNSUPPORTED, error: 'osv-scanner binary missing' });
  if (!ctx.inv.lockfiles.length) {
    return envelope('osv', { status: STATUS.SKIPPED, notes: ['no lockfile: SCA impossible, which is a COVERAGE GAP and not a clean result'], coverage: { filesSeen: ctx.inv.totalFiles, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  }
  const out = path.join(ctx.work, 'osv.json');
  const r = run(bin, ['scan', 'source', '--format', 'json', '--output', out, root], { timeoutMs: ctx.budget('osv') });
  if (!fs.existsSync(out)) return envelope('osv', { status: STATUS.ERROR, cost: r.cost, error: 'osv produced no output', notes: [String(r.stderr).slice(0, 200)] });
  const j = JSON.parse(fs.readFileSync(out, 'utf8'));
  const findings = [];
  for (const res of j.results || []) for (const pkg of res.packages || []) for (const v of pkg.vulnerabilities || []) {
    findings.push({ tool: 'osv', kind: 'sca', rule: v.id, level: (v.severity || []).map((s) => s.score).join(','), file: path.join(root, 'package.json'), detail: `${(pkg.package && (pkg.package.name || pkg.package.source)) || '?'}@${(pkg.package && pkg.package.version) || '?'}`, pkg: (pkg.package && pkg.package.name) || null });
  }
  return envelope('osv', { findings, cost: r.cost, rawArtifact: out, coverage: { filesSeen: ctx.inv.totalFiles, filesEligible: ctx.inv.totalFiles, filesParsed: ctx.inv.totalFiles, analysisCompleted: true } });
}

module.exports = { sentinel: sentinelCloud, normalizeCloudSignals, cloudSignalCategory, codeql, semgrep, bandit, shellcheck, trivy, osv };
