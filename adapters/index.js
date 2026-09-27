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
const { STATUS, envelope, run, expand, dirBytes, gitOut, snippet } = require('../lib/core');

const abs = (root, p) => path.resolve(root, String(p || '').replace(/\\/g, '/'));

// ---------------------------------------------------------------- sentinel
/** Vendored Sentinel defensive engine. Breadth signal, never a verdict. */
function sentinel(root, ctx) {
  const cli = ctx.tools.sentinelPurple.cli;
  if (!fs.existsSync(cli)) return envelope('sentinel', { status: STATUS.UNSUPPORTED, error: 'sentinel CLI missing' });
  const r = run('node', [cli, ctx.tools.sentinelPurple.modes.defensive, root], { cwd: path.dirname(cli), timeoutMs: ctx.budget('sentinel') });
  const i = String(r.stdout).search(/[[{]/);
  let j = null; try { j = i < 0 ? null : JSON.parse(String(r.stdout).slice(i)); } catch (e) { /* tool error */ }
  if (!j) {
    return envelope('sentinel', { status: STATUS.ERROR, cost: r.cost, error: 'sentinel produced no parseable output', notes: [String(r.stderr).slice(0, 300)] });
  }
  const obs = j.observations || j.findings || [];
  return envelope('sentinel', {
    findings: obs.map((o) => ({
      tool: 'sentinel', kind: o.kind || o.type || 'observation',
      file: abs(root, o.file || o.filePath || o.path), line: o.line || null,
      detail: String(o.message || o.detail || o.title || '').slice(0, 160),
    })),
    coverage: { filesSeen: invCount(ctx), filesEligible: invCount(ctx), filesParsed: invCount(ctx), analysisCompleted: true },
    cost: r.cost,
    notes: ['breadth signal only; never adjudicate exploitability from this'],
  });
}
const invCount = (ctx) => (ctx.inv ? ctx.inv.sourceFiles : 0);

// ---------------------------------------------------------------- purple
/**
 * Purple = attack hypothesis. Its output is candidate only, by contract.
 * runScoped=true restricts it to the files Sentinel flagged, which is the
 * point of the incremental pipeline: do not walk 33k files to re-derive a
 * shortlist some other lens already produced.
 */
function purple(root, ctx, opts = {}) {
  const cli = ctx.tools.sentinelPurple.cli;
  if (!fs.existsSync(cli)) return envelope('purple', { status: STATUS.UNSUPPORTED, error: 'purple CLI missing' });
  const scope = opts.scope && opts.scope.length ? opts.scope : null;
  const target = scope && scope.length === 1 ? scope[0] : root;
  const out = path.join(ctx.work, 'purple');
  fs.mkdirSync(out, { recursive: true });
  const r = run('node', [cli, ctx.tools.sentinelPurple.modes.expediente, target, '--out', out],
    { cwd: path.dirname(cli), timeoutMs: ctx.budget('purple') });
  const apPath = path.join(out, '02-attack-paths.json');
  const mfPath = path.join(out, 'audit-manifest.json');
  if (!fs.existsSync(apPath)) {
    return envelope('purple', { status: STATUS.ERROR, cost: r.cost, error: 'purple produced no 02-attack-paths.json', notes: [String(r.stderr).slice(0, 300)] });
  }
  const ap = JSON.parse(fs.readFileSync(apPath, 'utf8'));
  const mf = fs.existsSync(mfPath) ? JSON.parse(fs.readFileSync(mfPath, 'utf8')) : null;
  const edges = Array.isArray(ap.edges) ? ap.edges : [];
  const mfCov = mf ? { filesSeen: mf.filesHashed, filesEligible: mf.filesHashed, filesParsed: mf.filesHashed, analysisCompleted: true } : { analysisCompleted: true };
  return envelope('purple', {
    findings: edges.map((e) => ({
      tool: 'purple', kind: 'attack_path', verdictFromTool: e.verdict,
      source: e.source, sink: e.sink, sourceTrust: e.sourceTrust, sinkSeverity: e.sinkSeverity,
      file: abs(root, e.sinkFile || e.sourceFile), sourceFile: abs(root, e.sourceFile),
      line: e.sinkLocation && e.sinkLocation.start, sourceLine: e.sourceLocation && e.sourceLocation.start,
      scopeFromTool: e.analysisScope, controls: e.controls || [], blockedBy: e.blockedBy || [],
      reason: (e.reasons || []).join(';'), sha256: e.contentSha256 || null,
    })),
    coverage: mfCov,
    cost: Object.assign(r.cost, { artifactBytes: dirBytes(out) }),
    rawArtifact: apPath,
    notes: [
      'Purple ENTAILED is a candidate, never a vulnerability (measured 0 TP / 2 FP).',
      'Every candidate requires a location sanity check before any disposition.',
    ],
    manifest: mf ? { targetHash: mf.targetHash, scannerVersion: mf.scannerVersion, analysisMode: mf.analysisMode, networkUsed: mf.networkUsed, llmInDecisionPath: mf.llmInDecisionPath } : null,
  });
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
function bandit(root, ctx) {
  const bin = expand(ctx.tools.bandit.bin);
  if (!fs.existsSync(bin)) return envelope('bandit', { status: STATUS.UNSUPPORTED, error: 'bandit binary missing' });
  if (!(ctx.inv.byLang.python || 0)) return envelope('bandit', { status: STATUS.SKIPPED, notApplicable: true, notes: ['no python source in target: bandit not applicable'], coverage: { filesSeen: 0, filesEligible: 0, filesParsed: 0, analysisCompleted: true } });
  const out = path.join(ctx.work, 'bandit.json');
  const r = run(bin, ['-r', root, '-f', 'json', '-o', out, '-q'], { timeoutMs: ctx.budget('bandit') });
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
function shellcheck(root, ctx) {
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
  const findings = [];
  let cost = { wallClockMs: 0, timedOut: false };
  const CHUNK = 20;
  for (let i = 0; i < files.length; i += CHUNK) {
    const batch = files.slice(i, i + CHUNK);
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

module.exports = { sentinel, purple, codeql, semgrep, bandit, shellcheck, trivy, osv };
