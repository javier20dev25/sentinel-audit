'use strict';
/**
 * Preflight (Gate D + cost estimation).
 *
 * Answers, before a single expensive byte is spent:
 *   - is there a disclosure channel at all?
 *   - is the language actually supported by an installed analyzer?
 *   - how big is the real analyzable surface, and what will that cost?
 *   - is this worth auditing at all?
 *
 * Verdict: AUDIT_READY | AUDIT_LIMITED | SKIP
 */
const fs = require('fs');
const path = require('path');
const { loadConfig, inventory, gitOut, gitTracked, gitHas, run, STATUS, which, expand } = require('../lib/core');

function detectDisclosure(root, inv, policies, tracked) {
  const d = policies.disclosure;
  // A policy counts only if git tracks it. Untracked SECURITY.md files in a
  // shallow clone or a leftover checkout are not a maintainer commitment.
  const sourceOfTruth = tracked ? 'git ls-files' : 'filesystem (target is not a git checkout)';
  const wanted = [];
  const seenPaths = new Set();
  for (const rel of d.policyFiles) {
    const trackedHere = gitHas(tracked, rel);
    if (trackedHere === false) continue;            // proven not tracked
    if (trackedHere === null && !fs.existsSync(path.join(root, rel))) continue;
    const full = path.join(root, rel);
    if (trackedHere !== true && !fs.existsSync(full)) continue;
    const real = (() => { try { return fs.realpathSync(full).toLowerCase(); } catch (e) { return full.toLowerCase(); } })();
    if (seenPaths.has(real)) continue;
    seenPaths.add(real);
    wanted.push({ rel, full, tracked: trackedHere === true });
  }

  const EMAIL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
  const score = (txt) => {
    const low = txt.toLowerCase();
    const signals = d.privateVettingSignals.filter((s) => low.includes(s));
    const emails = [...new Set(txt.match(EMAIL) || [])];
    // A monitored security inbox is a vetted channel. "security@" is not the only
    // shape it takes: nestjs ships support@nestjs.com, and a narrow list would have
    // downgraded a real, monitored disclosure route to "no vetting".
    const emailVetted = d.emailAddressCountsAsVetted && emails.length > 0;
    return { signals, emails, vetted: signals.length > 0 || emailVetted, emailVetted };
  };

  const found = wanted.map(({ rel, full, tracked }) => {
    const txt = fs.existsSync(full) ? fs.readFileSync(full, 'utf8').slice(0, 8000) : '';
    const s = score(txt);
    return { file: rel, tracked, bytes: txt.length, vetted: s.vetted, signals: s.signals, contacts: s.emails, channel: s.vetted ? 'VETTED' : 'UNSPECIFIED' };
  });

  if (!found.length) {
    for (const rel of ['CONTRIBUTING.md', '.github/CONTRIBUTING.md', 'README.md', 'readme.md']) {
      const p = path.join(root, rel);
      if (!fs.existsSync(p)) continue;
      const txt = fs.readFileSync(p, 'utf8').slice(0, 8000);
      const s = score(txt);
      if (s.vetted) { found.push({ file: rel, bytes: txt.length, vetted: true, signals: s.signals, contacts: s.emails, channel: 'EMBEDDED' }); break; }
    }
  }
  const vetted = found.some((f) => f.vetted);
  return {
    hasPolicy: found.length > 0,
    vetted,
    sourceOfTruth,
    files: found.map((f) => f.file),
    contacts: [...new Set(found.flatMap((f) => f.contacts))],
    evidence: found,
    verdict: !found.length ? 'NO_DISCLOSURE_CHANNEL' : vetted ? 'DISCLOSURE_READY' : 'DISCLOSURE_POLICY_NO_VETTING',
  };
}

/** License, also from git. Absence is a policy limit, never silently assumed. */
function detectLicense(root, tracked) {
  if (tracked) {
    for (const p of tracked) {
      const base = p.split('/').pop();
      if (/^(licen[cs]e|copying)(\.[a-z]+)?$/i.test(base)) {
        return { present: true, file: p, sourceOfTruth: 'git ls-files' };
      }
    }
    return { present: false, file: null, sourceOfTruth: 'git ls-files' };
  }
  try {
    for (const e of fs.readdirSync(root)) {
      if (/^(licen[cs]e|copying)(\.[a-z]+)?$/i.test(e) && fs.statSync(path.join(root, e)).isFile()) {
        return { present: true, file: e, sourceOfTruth: 'filesystem (not a git checkout)' };
      }
    }
  } catch (e) { /* unreadable root is reported elsewhere */ }
  return { present: false, file: null, sourceOfTruth: 'filesystem (not a git checkout)' };
}

function checkToolHealth(tools) {
  const health = {};
  for (const key of ['codeql', 'semgrep', 'trivy', 'osv', 'bandit', 'shellcheck']) {
    const t = tools[key];
    if (!t) { health[key] = { available: false, reason: 'not configured' }; continue; }
    const bin = expand(t.bin);
    if (!fs.existsSync(bin) && !/^semgrep$/i.test(bin)) {
      health[key] = { available: false, reason: 'binary not found', path: bin };
      continue;
    }
    const w = which(bin);
    health[key] = { available: w.available, version: w.version, path: bin };
  }
  // Sentinel-purple must exist and be untouched; it is an input, not a dependency we install.
  const sp = tools.sentinelPurple;
  health.sentinel = fs.existsSync(sp.cli)
    ? { available: true, repo: sp.repo, head: gitOut(sp.repo, 'rev-parse', '--short', 'HEAD'), dirty: !!gitOut(sp.repo, 'status', '--porcelain') }
    : { available: false, reason: 'sentinel-purple CLI missing' };
  return health;
}

function estimateCost(inv, health, policies) {
  const b = policies.budget;
  const production = inv.production || 0;
  const source = inv.sourceFiles || 0;
  // Measured on ANALYZABLE SOURCE, not production files. Production count hides
  // monorepo weight: next.js ships 3301 production files but 25154 analysable
  // ones, and CodeQL OOMed on the default heap until it was given 8192MB.
  const large = source > b.codeqlLargeRepoFiles;
  const codeqlMinutes = large ? b.perToolMinutes.codeql : Math.max(2, Math.round(source / 900));
  return {
    productionSourceFiles: production,
    analyzableSourceFiles: source,
    largeRepo: large,
    largeRepoBasis: 'analyzableSourceFiles',
    estimateMinutes: {
      codeql: codeqlMinutes,
      semgrep: Math.min(b.perToolMinutes.semgrep, Math.max(2, Math.round(inv.totalFiles / 1500))),
      trivy: Math.min(b.perToolMinutes.trivy, Math.max(1, Math.round(inv.totalFiles / 3000))),
      osv: inv.lockfiles.length ? Math.min(b.perToolMinutes.osv, 4) : 0,
      bandit: inv.byLang.python ? b.perToolMinutes.bandit : 0,
      shellcheck: inv.byLang.shell ? Math.min(b.perToolMinutes.shellcheck, 4) : 0,
    },
    totalEstimateMinutes: 0,
    requiredRamMB: large ? b.codeqlLargeRepoRam : b.codeqlDefaultRam,
    fitsBudget: false,
    notes: [],
  };
}

function preflight(repoPath, opts = {}) {
  const { tools, policies } = loadConfig();
  const reasons = [];
  const limits = [];
  const root = path.resolve(repoPath);

  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return { repo: root, name: opts.name || path.basename(root), verdict: 'SKIP', reasons: ['path does not exist or is not a directory'], limits, health: {}, inv: null, disclosure: null, cost: null, status: STATUS.ERROR, checkedAt: new Date().toISOString() };
  }
  const isGit = fs.existsSync(path.join(root, '.git'));
  if (!isGit) reasons.push('not a git checkout');
  const tracked = isGit ? gitTracked(root) : null;
  if (isGit && !tracked) limits.push('git ls-files failed: policy and license cannot be verified against git');

  const inv = inventory(root, policies);
  const disclosure = detectDisclosure(root, inv, policies, tracked);
  const license = detectLicense(root, tracked);
  const health = checkToolHealth(tools);

  if (!license.present) limits.push('no tracked LICENSE file: usage terms unverified');
  if (!inv.securityPolicy && disclosure.verdict === 'NO_DISCLOSURE_CHANNEL') {
    limits.push('no SECURITY.md and no vetted reporting channel');
  } else if (!disclosure.vetted) {
    limits.push('SECURITY.md present but no private-vetting signal found');
  }
  if (!inv.sourceFiles) reasons.push('no source files in any analyzable language');
  if (inv.sourceFiles && inv.production === 0) reasons.push('every source file is test/example/vendor/generated');
  if (!inv.lockfiles.length) limits.push('no lockfile: SCA will be a coverage gap, not a clean result');
  if (!health.codeql.available) limits.push('codeql unavailable');
  if (health.sentinel && health.sentinel.available && health.sentinel.dirty) limits.push('sentinel-purple worktree is dirty; pinned-input contract violated');

  const cost = estimateCost(inv, health, policies);
  cost.totalEstimateMinutes = Object.values(cost.estimateMinutes).reduce((a, b) => a + b, 0);
  cost.fitsBudget = cost.totalEstimateMinutes <= policies.budget.totalWallClockMinutes;
  if (!cost.fitsBudget) {
    limits.push(`estimated ${cost.totalEstimateMinutes}m exceeds ${policies.budget.totalWallClockMinutes}m wall-clock budget`);
    if (cost.largeRepo) cost.notes.push('large repo: consider scoping CodeQL to production paths only');
  }
  if (inv.productionRatio < 0.25 && inv.sourceFiles > 20) {
    cost.notes.push(`only ${(inv.productionRatio * 100).toFixed(0)}% of source is production; scope analysis to production paths`);
  }

  const supported = inv.languages.filter((l) => policies.readiness.supportedLanguages.includes(l));
  const analyzerReady = supported.some((l) => l === 'javascript' || l === 'typescript' ? health.codeql.available : true);

  let verdict = 'AUDIT_READY';
  if (reasons.length) verdict = 'SKIP';
  else if (limits.length) verdict = 'AUDIT_LIMITED';

  return {
    repo: root,
    name: opts.name || path.basename(root),
    commit: isGit ? gitOut(root, 'rev-parse', 'HEAD') : null,
    tree: isGit ? gitOut(root, 'rev-parse', 'HEAD^{tree}') : null,
    shallow: isGit ? gitOut(root, 'rev-parse', '--is-shallow-repository') : null,
    verdict,
    reasons,
    limits,
    disclosure,
    license,
    trackedFileCount: tracked ? tracked.size : null,
    inv,
    supportedLanguages: supported,
    analyzerReady,
    health,
    cost,
    checkedAt: new Date().toISOString(),
  };
}

module.exports = { preflight, detectDisclosure, detectLicense, checkToolHealth, estimateCost };
