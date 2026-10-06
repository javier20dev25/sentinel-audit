'use strict';
// Sentinel Audit v1 core contracts.
/**
 * Core primitives for Sentinel Audit Runner.
 *
 * The whole point of this file is Gate A/B/C from Audit Readiness v1:
 * a tool result is never a bare count. It is an envelope that always carries
 *   - status      (SUCCESS | PARTIAL | ERROR | UNSUPPORTED | SKIPPED)
 *   - coverage    (what was actually looked at)
 *   - cost        (what it consumed)
 * so that "0 findings" can never be mistaken for "clean".
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const STATUS = {
  SUCCESS: 'SUCCESS',
  PARTIAL: 'PARTIAL',
  ERROR: 'ERROR',
  UNSUPPORTED: 'UNSUPPORTED',
  SKIPPED: 'SKIPPED',
  UNAVAILABLE: 'UNAVAILABLE',
  INVALID: 'INVALID',
  TIMEOUT: 'TIMEOUT',
  CANCELLED: 'CANCELLED',
};

const expand = (p) =>
  String(p)
    .replace(/%LOCALAPPDATA%/gi, process.env.LOCALAPPDATA || '')
    .replace(/%USERPROFILE%/gi, process.env.USERPROFILE || '')
    .replace(/%HOME%/gi, process.env.USERPROFILE || process.env.HOME || '')
    .replace(/%TEMP%/gi, process.env.TEMP || '');

const loadConfig = () => {
  const tools = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config', 'tools.json'), 'utf8'));
  const policies = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config', 'policies.json'), 'utf8'));
  return { tools, policies };
};

const nowMs = () => Date.now();

/** Fresh, empty coverage counters. Every field is a real observation, never a guess. */
function emptyCoverage() {
  return {
    filesSeen: null, filesEligible: null, filesParsed: null, filesSkippedBinary: null,
    filesSkippedTooLarge: null, filesSkippedUnderscoreDir: null, filesExcludedVendor: null,
    filesExcludedTest: null, filesExcludedNonProduction: null, filesExcludedGenerated: null,
    parseErrors: null, parseErrorFiles: [], unsupportedFiles: null,
    analysisCompleted: false,
    engineExecutionComplete: null, engineIncomplete: null,
    coverageKnown: false, coverageUnknown: true,
    filesScanned: null, filesFailed: null, alertsSeen: null, alertsEnrichFailed: null,
    degradationSamples: null,
    errors: [],
  };
}

/**
 * Build the uniform envelope. `coverage` and `cost` are mandatory: a caller that
 * cannot measure them must say so rather than defaulting them to healthy.
 */
function envelope(tool, opts = {}) {
  const cov = Object.assign(emptyCoverage(), opts.coverage || {});
  const cost = Object.assign(
    { wallClockMs: 0, timedOut: false, peakRamMB: null, dbBytes: null, artifactBytes: null, overBudget: false },
    opts.cost || {}
  );
  let status = opts.status || STATUS.SUCCESS;
  // Derive degradation that a naive harness would miss.
  if (!opts.status) {
    if (cost.timedOut || cost.overBudget) status = STATUS.PARTIAL;
    else if (cov.coverageUnknown === true) status = STATUS.PARTIAL;
    else if (cov.parseErrors > 0 || !cov.analysisCompleted) status = cov.analysisCompleted ? STATUS.PARTIAL : STATUS.ERROR;
    else if (cov.filesEligible > 0 && cov.filesParsed === 0) status = STATUS.PARTIAL;
  }
  const find = Array.isArray(opts.findings) ? opts.findings : [];
  // "No Python in this repo" is not a degradation. Bandit not running on a
  // TypeScript monorepo tells you nothing about the repo's security, and it
  // must not be laundered into either a clean signal or a dirty one.
  const notApplicable = !!opts.notApplicable;
  return {
    tool,
    status,
    verdict: notApplicable ? 'NOT_APPLICABLE' : verdictFor(status, find.length, cov),
    notApplicable,
    version: opts.version || null,
    // Carried through so the persisted job record explains *why* a tool did not
    // run.  Without it every specialist shows availability UNKNOWN in the report
    // and the real resolution is lost.
    availability: opts.availability || null,
    findings: find,
    findingCount: find.length,
    signalCounts: opts.signalCounts || null,
    coverage: cov,
    cost,
    notes: opts.notes || [],
    rawArtifact: opts.rawArtifact || null,
    error: opts.error || null,
    // Carried through so the persisted specialist-jobs ledger records jobId,
    // state and duration for every tool that actually ran.  Without it an
    // executed specialist and a tool that was never scheduled produce the same
    // record, which is exactly the distinction an audit has to be able to make.
    job: opts.job || null,
  };
}

/** A finding count is only meaningful next to coverage. This is the sentence that stops the mistake. */
function verdictFor(status, n, cov) {
  switch (status) {
    case STATUS.SUCCESS: return n === 0 ? 'NO_SIGNALS_FULL_COVERAGE' : `${n}_SIGNALS_FULL_COVERAGE`;
    case STATUS.PARTIAL: return n === 0 ? 'NO_SIGNALS_LIMITED_COVERAGE' : `${n}_SIGNALS_LIMITED_COVERAGE`;
    case STATUS.ERROR: return 'TOOL_ERROR';
    case STATUS.UNSUPPORTED: return 'UNSUPPORTED';
    case STATUS.SKIPPED: return 'SKIPPED';
    case STATUS.UNAVAILABLE: return 'SPECIALIST_UNAVAILABLE';
    case STATUS.INVALID: return 'SPECIALIST_INVALID';
    case STATUS.TIMEOUT: return 'TOOL_TIMEOUT';
    case STATUS.CANCELLED: return 'TOOL_CANCELLED';
    default: return 'UNKNOWN';
  }
}

/** Metered spawn. Returns stdout/stderr plus real cost, and never throws. */
function run(cmd, args, opts = {}) {
  const t0 = nowMs();
  const res = spawnSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    timeout: opts.timeoutMs || 0,
    cwd: opts.cwd,
    env: Object.assign({}, process.env, opts.env || {}),
    windowsHide: true,
  });
  const wall = nowMs() - t0;
  return {
    ok: res.status === 0,
    status: res.status,
    signal: res.signal || null,
    stdout: res.stdout || '',
    stderr: res.stderr || '',
    error: res.error ? String(res.error.message) : null,
    cost: { wallClockMs: wall, timedOut: !!(res.error && /timed out|ETIMEDOUT/i.test(String(res.error.message))) },
  };
}

const which = (bin) => {
  const r = run(bin, ['--version'], { timeoutMs: 60000 });
  return { available: r.ok || r.stdout.length > 0, version: (r.stdout || r.stderr || '').split('\n')[0].trim() };
};

function dirBytes(p) {
  if (!fs.existsSync(p)) return 0;
  let total = 0;
  const stack = [p];
  while (stack.length) {
    const d = stack.pop();
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { continue; }
    for (const e of ents) {
      const f = path.join(d, e.name);
      if (e.isDirectory()) stack.push(f);
      else { try { total += fs.statSync(f).size; } catch (err) { /* ignore */ } }
    }
  }
  return total;
}

const gitOut = (repo, ...a) => {
  const resolved = path.resolve(repo);
  const r = run('git', ['-c', `safe.directory=${resolved}`, '-C', resolved, ...a], { timeoutMs: 60000 });
  return r.ok ? r.stdout.trim() : null;
};

/**
 * Source of truth for anything the audit asserts about a target is GIT, not the
 * filesystem. A shallow clone, a worktree, or a leftover checkout can all carry
 * an untracked SECURITY.md that no maintainer has ever agreed to; conversely a
 * tracked policy is a commitment even if the file is absent from disk. Proving
 * "0 of 12 targets have a policy" from `existsSync` is how the previous campaign
 * got that number wrong.
 */
function gitTracked(repo) {
  const resolved = path.resolve(repo);
  const r = run('git', ['-c', `safe.directory=${resolved}`, '-C', resolved, 'ls-files', '-z'], { timeoutMs: 120000 });
  if (!r.ok || !r.stdout) return null;
  return new Set(r.stdout.split('\0').filter(Boolean).map((p) => p.replace(/\\/g, '/')));
}

/** Resolve whether a repo-relative path is tracked, case-insensitively on win32. */
const gitHas = (tracked, relPath) => {
  if (!tracked) return null;
  const norm = String(relPath).replace(/\\/g, '/');
  if (tracked.has(norm)) return true;
  const low = norm.toLowerCase();
  for (const p of tracked) if (p.toLowerCase() === low) return true;
  return false;
};

/** Classify one file: which bucket, and why. Used for both coverage and scope sanity checks. */
function classifyFile(rel, policies) {
  const lower = '/' + rel.replace(/\\/g, '/').toLowerCase();
  const parts = lower.split('/');
  const base = parts[parts.length - 1];
  const isTest = policies.coverage.testPathHints.some((h) => lower.includes(h) || base.includes(h.replace(/\//g, '')));
  const isNonProd = policies.coverage.nonProductionPathHints.some((h) => lower.includes(h));
  const isVendor = parts.some((p) => ['node_modules', 'vendor', 'third_party', 'dist', 'build'].includes(p));
  const isGenerated = /\.(min\.js|bundle\.js|generated\.[tj]s|lock)$/.test(base) || base.includes('.pb.') || lower.includes('/__snapshots__/');
  return { isTest, isNonProd, isVendor, isGenerated, inProduction: !isTest && !isNonProd && !isVendor && !isGenerated };
}

const EXT_LANG = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.py': 'python', '.pyi': 'python',
  '.go': 'go', '.java': 'java', '.cs': 'csharp', '.c': 'cpp', '.h': 'cpp', '.cpp': 'cpp',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
  '.rb': 'ruby', '.php': 'php', '.rs': 'rust', '.scala': 'scala', '.kt': 'kotlin', '.swift': 'swift',
};

/** Walk a repo once and produce the real inventory the preflight and coverage gates need. */
function inventory(root, policies) {
  const skipDirs = new Set(policies.coverage.skipDirs);
  const maxBytes = policies.coverage.maxFileBytes;
  const inv = {
    totalFiles: 0, byExt: {}, byLang: {}, sourceFiles: 0,
    production: 0, test: 0, nonProduction: 0, vendor: 0, generated: 0, oversized: 0, binaryish: 0,
    lockfiles: [], manifests: [], securityPolicy: null, license: null,
    largestDirs: [],
  };
  const walk = (d, depth, rel) => {
    if (depth > 24) return;
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
    for (const e of ents) {
      if (e.isDirectory()) {
        if (skipDirs.has(e.name)) { inv.vendor++; continue; }
        walk(path.join(d, e.name), depth + 1, rel ? rel + '/' + e.name : e.name);
        continue;
      }
      const full = path.join(d, e.name);
      const r = rel ? rel + '/' + e.name : e.name;
      inv.totalFiles++;
      const ext = path.extname(e.name).toLowerCase();
      inv.byExt[ext] = (inv.byExt[ext] || 0) + 1;
      let st; try { st = fs.statSync(full); } catch (err) { continue; }
      // Presence detection must not depend on file size.  A large lockfile is
      // exactly where dependency risk concentrates, and dropping it here made
      // SCA report "not applicable" on the repository with the biggest lockfile
      // instead of reporting a coverage gap.  The size guard below is about
      // parsing content, not about deciding what the repository contains.
      if (/^(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements\.txt|poetry\.lock|Pipfile\.lock|go\.sum|Cargo\.lock|composer\.lock|Gemfile\.lock)$/.test(e.name)) inv.lockfiles.push(r);
      if (/^(package\.json|pyproject\.toml|setup\.py|requirements\.txt|go\.mod|Cargo\.toml|pom\.xml|build\.gradle)$/.test(e.name)) inv.manifests.push(r);
      if (/^LICENSE/i.test(e.name) && !inv.license) inv.license = r;
      if (/^SECURITY\.md$/i.test(e.name) && !inv.securityPolicy) inv.securityPolicy = r;
      if (st.size > maxBytes) { inv.oversized++; continue; }
      if (st.size === 0) continue;
      const textish = ['.md', '.json', '.yml', '.yaml', '.txt', '.toml', '.lock', '.env', '.sql', '.html', '.css', '.xml', '.ini', '.cfg'].includes(ext) || EXT_LANG[ext];
      if (!textish) { inv.binaryish++; continue; }
      const lang = EXT_LANG[ext];
      if (lang) {
        inv.byLang[lang] = (inv.byLang[lang] || 0) + 1;
        inv.sourceFiles++;
        const c = classifyFile(r, policies);
        if (c.isVendor) inv.vendor++;
        else if (c.isTest) inv.test++;
        else if (c.isNonProd) inv.nonProduction++;
        else if (c.isGenerated) inv.generated++;
        else inv.production++;
      }
    }
  };
  walk(root, 0, '');
  inv.languages = Object.keys(inv.byLang).sort((a, b) => inv.byLang[b] - inv.byLang[a]);
  inv.mainLanguage = inv.languages[0] || null;
  inv.productionRatio = inv.sourceFiles ? +(inv.production / inv.sourceFiles).toFixed(3) : 0;
  inv.nonShippedRatio = inv.sourceFiles ? +(((inv.test + inv.nonProduction + inv.vendor + inv.generated) / inv.sourceFiles)).toFixed(3) : 0;
  return inv;
}

/** A finding is unreadable without the line it points at. Capture it once, here. */
function snippet(root, file, line, radius = 2) {
  try {
    if (!file || !fs.existsSync(file)) return null;
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    const n = Number(line);
    if (!n || n < 1 || n > lines.length) return null;
    const from = Math.max(0, n - 1 - radius);
    const to = Math.min(lines.length, n + radius);
    return { from: from + 1, to, text: lines.slice(from, to).map((l, i) => `${String(from + i + 1).padStart(5)} | ${l}`).join('\n') };
  } catch (e) {
    return null;
  }
}

module.exports = { STATUS, loadConfig, envelope, emptyCoverage, verdictFor, run, which, dirBytes, gitOut, gitTracked, gitHas, snippet, inventory, classifyFile, expand, EXT_LANG };
