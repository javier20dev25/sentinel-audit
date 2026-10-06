'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { gitOut, run, expand } = require('../lib/core');

const sha256 = (file) => fs.existsSync(file)
  ? crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')
  : null;

function gitIdentity(root) {
  const commit = gitOut(root, 'rev-parse', 'HEAD');
  const tree = gitOut(root, 'rev-parse', 'HEAD^{tree}');
  const status = run('git', ['-c', `safe.directory=${root}`, '-C', root, 'status', '--porcelain', '--untracked-files=all'], { timeoutMs: 30000 });
  return {
    commit,
    tree,
    workingTreeClean: status.ok ? status.stdout.trim().length === 0 : null,
    workingTreeStatus: status.ok ? status.stdout.trim() : null,
  };
}

function buildIdentity({ executionId, repo, preflight, tools, startedAt, sourceRepository = null }) {
  const projectRoot = path.resolve(__dirname, '..');
  const runnerGit = gitIdentity(projectRoot);
  const engine = preflight && preflight.health && preflight.health.sentinel;
  const engineFiles = preflight && preflight.health && preflight.health.sentinelFiles || {};
  const hashes = {};
  for (const rel of [
    'audit-runner.js', 'workflow/preflight.js', 'workflow/audit.js', 'workflow/identity.js',
    'adapters/index.js', 'correlate/index.js', 'lib/core.js', 'reports/expediente.js',
    'config/tools.json', 'config/policies.json',
  ]) hashes[rel] = sha256(path.join(projectRoot, rel));
  const toolRuleHashes = {};
  for (const [name, cfg] of Object.entries(require('../lib/core').loadConfig().tools)) {
    if (cfg && cfg.suites) toolRuleHashes[name] = Object.fromEntries(Object.entries(cfg.suites).map(([language, suite]) => [language, sha256(expand(suite))]));
    if (cfg && Array.isArray(cfg.configs)) toolRuleHashes[name] = { configs: cfg.configs, configSha256: sha256(path.join(projectRoot, 'config', 'tools.json')) };
  }
  return {
    schema: 'sentinel-audit-identity/1.0.0',
    executionId,
    startedAt,
    repository: repo,
    sourceRepository: sourceRepository || repo,
    target: gitIdentity(repo),
    remoteUrl: preflight && preflight.remoteUrl || gitOut(repo, 'config', '--get', 'remote.origin.url'),
    audit: {
      revision: runnerGit.commit,
      tree: runnerGit.tree,
      workingTreeClean: runnerGit.workingTreeClean,
      workingTreeStatus: runnerGit.workingTreeStatus,
      fileSha256: hashes,
    },
    engine: engine ? {
      product: 'Sentinel Cloud worker engine (direct local invocation)',
      revision: engine.head || null,
      scannerSha256: engine.engineSha256 || null,
      astInspectorSha256: engine.astInspectorSha256 || null,
      configSha256: engine.configSha256 || null,
      productionParity: engine.productionParity || 'UNKNOWN',
    } : null,
    specialistVersions: tools || {},
    specialistRuleHashes: toolRuleHashes,
    configurationSha256: {
      tools: hashes['config/tools.json'],
      policies: hashes['config/policies.json'],
      routing: hashes['workflow/audit.js'],
    },
  };
}

module.exports = { sha256, gitIdentity, buildIdentity };
