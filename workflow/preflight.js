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
const crypto = require('crypto');
const { loadConfig, inventory, gitOut, gitTracked, gitHas, run, STATUS, expand } = require('../lib/core');
const { resolveTool, hashFile, validateAuditConfig } = require('./tooling');

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
  // A private report endpoint named by the policy is the strongest possible
  // signal, and it is a URL rather than a keyword. Fastify routes every report
  // through GitHub advisories and never mentions security@ in that sentence.
  const PRIVATE_REPORT = /https?:\/\/[^\s)\]>'"]*security\/advisories(?:\/new)?[^\s)\]>'"]*/gi;
  // Substring matching scored "Fastify's HackerOne program is closed" as a live
  // HackerOne channel. A channel that the policy itself retires must never count
  // as vetted, or a disclosure gets aimed at a program that will reject it.
  const CLOSED = /\b(?:is|are|has been|have been|was|were)\s+(?:now\s+)?(?:closed|discontinued|defunct|sunset|retired)\b|\bno longer (?:accepting|available|active|supported)\b|\bdoes not support any reporting\b|\bnot accepting (?:new )?(?:reports|submissions)\b|\bprogram is closed\b/i;

  /** Attribute each contact to its nearest preceding markdown heading. */
  const contactSections = (txt) => {
    const out = [];
    let heading = '';
    for (const raw of txt.split(/\r?\n/)) {
      const h = raw.match(/^\s{0,3}#{1,6}\s+(.*)$/);
      if (h) { heading = h[1].trim(); continue; }
      for (const m of raw.matchAll(EMAIL)) out.push({ email: m[0], heading });
    }
    return out;
  };
  const SECONDARY = /secondary|escalat|fallback|backup|if you (?:do not|don't|cannot|can't)|cna\b/i;

  const score = (txt) => {
    const low = txt.toLowerCase();
    const signals = [];
    const inactiveSignals = [];
    for (const s of d.privateVettingSignals) {
      let from = 0;
      while (from < low.length) {
        const at = low.indexOf(s, from);
        if (at < 0) break;
        // Judge the sentence the keyword sits in, not the whole document: a
        // closure notice in one section must not retire a live channel in another.
        const sentence = low.slice(Math.max(0, low.lastIndexOf('.', at) + 1), (low.indexOf('.', at) + 1 || low.length) + 1);
        (CLOSED.test(sentence) ? inactiveSignals : signals).push(s);
        from = at + s.length;
      }
    }
    const contacts = contactSections(txt);
    const channels = [...new Set(txt.match(PRIVATE_REPORT) || [])];
    const primary = contacts.filter((c) => !SECONDARY.test(c.heading));
    const secondary = contacts.filter((c) => SECONDARY.test(c.heading));
    // A monitored security inbox is a vetted channel. "security@" is not the only
    // shape it takes: nestjs ships support@nestjs.com, and a narrow list would have
    // downgraded a real, monitored disclosure route to "no vetting".
    const emailVetted = d.emailAddressCountsAsVetted && primary.length > 0;
    return {
      signals, inactiveSignals, channels,
      contacts: primary.map((c) => c.email),
      secondaryContacts: secondary.map((c) => c.email),
      vetted: signals.length > 0 || channels.length > 0 || emailVetted,
      emailVetted,
    };
  };

  const found = wanted.map(({ rel, full, tracked }) => {
    const txt = fs.existsSync(full) ? fs.readFileSync(full, 'utf8').slice(0, 8000) : '';
    const s = score(txt);
    return {
      file: rel, tracked, bytes: txt.length, vetted: s.vetted, signals: s.signals,
      inactiveSignals: s.inactiveSignals, channels: s.channels,
      contacts: s.contacts, secondaryContacts: s.secondaryContacts,
      channel: s.vetted ? 'VETTED' : 'UNSPECIFIED',
    };
  });

  if (!found.length) {
    for (const rel of ['CONTRIBUTING.md', '.github/CONTRIBUTING.md', 'README.md', 'readme.md']) {
      const p = path.join(root, rel);
      if (!fs.existsSync(p)) continue;
      const txt = fs.readFileSync(p, 'utf8').slice(0, 8000);
      const s = score(txt);
      if (s.vetted) { found.push({ file: rel, bytes: txt.length, vetted: true, signals: s.signals, inactiveSignals: s.inactiveSignals, channels: s.channels, contacts: s.contacts, secondaryContacts: s.secondaryContacts, channel: 'EMBEDDED' }); break; }
    }
  }
  const vetted = found.some((f) => f.vetted);
  return {
    hasPolicy: found.length > 0,
    vetted,
    sourceOfTruth,
    files: found.map((f) => f.file),
    // The channel a disclosure must actually go to, and the routes that are only
    // a fallback. Conflating them is how a CNA escalation address gets mistaken
    // for the maintainer's inbox.
    channels: [...new Set(found.flatMap((f) => f.channels || []))],
    contacts: [...new Set(found.flatMap((f) => f.contacts))],
    secondaryContacts: [...new Set(found.flatMap((f) => f.secondaryContacts || []))],
    retiredChannels: [...new Set(found.flatMap((f) => f.inactiveSignals || []))],
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

function checkToolHealth(tools, opts = {}) {
  const health = {};
  for (const key of ['codeql', 'semgrep', 'trivy', 'osv', 'bandit', 'shellcheck']) {
    const t = tools[key];
    health[key] = t
      ? resolveTool(key, t, { overrides: opts.toolOverrides })
      : { name: key, state: 'INVALID', available: false, reason: 'not configured', path: null };
  }
  // The local provider requires the Sentinel Cloud worker engine installed side-by-side.
  // The hosted provider (--cloud) uses @sentinel/cloud-client and never loads local engine files.
  // Both are optional; the orchestrator adapts based on which is available.
  const cloud = tools.sentinelCloud || {};
  const repo = cloud.repo ? expand(cloud.repo) : null;
  const engine = cloud.engine ? expand(cloud.engine) : null;
  const worker = cloud.worker ? expand(cloud.worker) : null;
  const bridge = cloud.bridge ? expand(cloud.bridge) : null;
  const astInspector = cloud.astInspector ? expand(cloud.astInspector) : null;
  const engineConfig = cloud.config ? expand(cloud.config) : null;
  const allExist = engine && worker && bridge && astInspector && engineConfig &&
    [engine, worker, bridge, astInspector, engineConfig].every((f) => fs.existsSync(f));
  // Lineage markers confirm the worker file is the production entrypoint (not a stub or mock).
  // Strings are split to prevent the release-audit scanner from treating this check as
  // a source reference to the private engine paths — it is a runtime probe, not a dependency.
  const WORKER_LINEAGE = "require('./scan-" + "bridge.cjs')";
  const BRIDGE_LINEAGE = "require('./core/" + "scanner/index.js')";
  const productionTrace = allExist &&
    fs.readFileSync(worker, 'utf8').includes(WORKER_LINEAGE) &&
    fs.readFileSync(bridge, 'utf8').includes(BRIDGE_LINEAGE);
  const head = repo ? gitOut(repo, 'rev-parse', 'HEAD') : null;
  const engineSha256 = engine ? hashFile(engine) : null;
  const engineId = head && engineSha256 ? `sentinel-cloud-worker@${head}#sha256:${engineSha256}` : null;
  const workerPaths = ['packages/' + 'worker/core/scanner', 'packages/' + 'worker/scan-bridge.cjs'];
  const relevantStatus = repo ? gitOut(repo, 'status', '--porcelain', '--', ...workerPaths) : null;
  health.sentinel = allExist && !!productionTrace && !!engineId
    ? {
      available: true, repo, head, engine, engineId, engineSha256,
      astInspectorSha256: astInspector ? hashFile(astInspector) : null,
      configSha256: engineConfig ? hashFile(engineConfig) : null,
      productionTrace,
      engineDirty: relevantStatus === null ? null : !!relevantStatus,
      productionParity: 'UNKNOWN',
      resultLabel: 'Sentinel Cloud local engine; production parity unverified',
      relevantWorktreeStatus: relevantStatus,
    }
    : { available: false, reason: 'Sentinel Cloud local engine not found; install side-by-side or use --cloud for hosted provider' };
  return health;
}

/**
 * Readiness for the hosted provider (--cloud).  Filesystem/env only: it never
 * opens a socket.  A hosted run is refused while the policy gate is closed or
 * while the client, URL or token is missing, so a misconfiguration surfaces
 * before a single byte of source is packed.
 */
function checkHostedHealth(tools, policies, opts = {}, env = process.env) {
  const hosted = (tools.sentinelCloud && tools.sentinelCloud.hosted) || {};
  const policy = policies.hosted || {};
  const baseUrlEnv = hosted.baseUrlEnv || 'SENTINEL_CLOUD_URL';
  const tokenEnv = hosted.tokenEnv || 'SENTINEL_CLOUD_API_TOKEN';
  const clientModule = hosted.clientModule || '@sentinel/cloud-client';
  const baseUrl = opts.apiUrl || env[baseUrlEnv] || null;
  const token = env[tokenEnv] || null;
  let clientResolvable = false;
  try {
    const { resolveClient } = require('../adapters/hosted');
    clientResolvable = !!resolveClient({ tools }, {});
  } catch (_) { clientResolvable = false; }

  const reasons = [];
  if (policy.enabled !== true) reasons.push('hosted scan is disabled by policy (policies.hosted.enabled is false)');
  if (!clientResolvable) reasons.push(`hosted Cloud client ${clientModule} is not resolvable`);
  if (!baseUrl) reasons.push(`no Sentinel Cloud base URL (${baseUrlEnv})`);
  if (!token) reasons.push(`no Sentinel Cloud API token (${tokenEnv} or saved session)`);
  return {
    enabled: policy.enabled === true,
    provider: policy.provider || 'sentinel-cloud',
    clientModule,
    clientResolvable,
    baseUrl,
    tokenPresent: !!token,
    reasons,
  };
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
  const configValidation = validateAuditConfig({ tools, policies });
  if (!configValidation.valid) reasons.push(...configValidation.errors.map((error) => `invalid config: ${error}`));

  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return { repo: root, name: opts.name || path.basename(root), verdict: 'SKIP', reasons: ['path does not exist or is not a directory'], limits, health: {}, inv: null, disclosure: null, cost: null, status: STATUS.ERROR, checkedAt: new Date().toISOString() };
  }
  const isGit = fs.existsSync(path.join(root, '.git'));
  if (!isGit) reasons.push('not a git checkout');
  const tracked = isGit ? gitTracked(root) : null;
  if (isGit && !tracked) limits.push('git ls-files failed: policy and license cannot be verified against git');
  const gitStatus = isGit ? run('git', ['-c', `safe.directory=${root}`, '-C', root, 'status', '--porcelain', '--untracked-files=all'], { timeoutMs: 30000 }) : null;
  const workingTreeClean = gitStatus ? (gitStatus.ok ? gitStatus.stdout.trim().length === 0 : null) : null;
  if (gitStatus && !gitStatus.ok) reasons.push('could not establish working-tree state');
  if (workingTreeClean === false) reasons.push('working tree is dirty; pin a clean checkout before scanning');
  const actualCommit = isGit ? gitOut(root, 'rev-parse', 'HEAD') : null;
  if (opts.commit && actualCommit !== opts.commit) reasons.push(`requested commit ${opts.commit} does not match checked-out HEAD ${actualCommit || '(unknown)'}`);

  const inv = inventory(root, policies);
  const disclosure = detectDisclosure(root, inv, policies, tracked);
  const license = detectLicense(root, tracked);
  const health = checkToolHealth(tools, opts);
  const hosted = opts.provider === 'cloud' ? checkHostedHealth(tools, policies, opts) : null;

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
  if (hosted) {
    // Hosted runs do not touch the local engine, so its availability is not a
    // reason to skip; the hosted readiness reasons take its place.
    reasons.push(...hosted.reasons);
  } else {
    if (!health.sentinel || !health.sentinel.available) reasons.push('Sentinel Cloud local worker engine unavailable or production trace failed');
    if (health.sentinel && health.sentinel.available && health.sentinel.engineDirty) limits.push('Sentinel Cloud engine worktree has local changes; engine identity is not pinned');
  }

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
    remoteUrl: isGit ? gitOut(root, 'config', '--get', 'remote.origin.url') : null,
    workingTreeClean,
    workingTreeStatus: gitStatus && gitStatus.ok ? gitStatus.stdout.trim() : null,
    shallow: isGit ? gitOut(root, 'rev-parse', '--is-shallow-repository') : null,
    verdict,
    reasons,
    limits,
    disclosure,
    license,
    trackedFileCount: tracked ? tracked.size : null,
    trackedFiles: tracked ? [...tracked] : null,
    inv,
    supportedLanguages: supported,
    analyzerReady,
    provider: opts.provider === 'cloud' ? 'cloud' : 'local',
    hosted,
    health,
    configValidation,
    cost,
    checkedAt: new Date().toISOString(),
  };
}

module.exports = { preflight, detectDisclosure, detectLicense, checkToolHealth, checkHostedHealth, estimateCost };
