'use strict';

// Controlled, static-only integration smoke. The fixture is written as text;
// it is never imported, evaluated, built, or executed.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const net = require('net');
const { loadConfig, expand } = require('../lib/core');
const adapters = require('../adapters');
const { sentinel, normalizeCloudSignals } = adapters;
const { buildRoutePlan } = require('../workflow/audit');

async function scanStaticFixture(root, work, tools, engineIdentity) {
  fs.mkdirSync(work, { recursive: true });
  const blockedNetworkAttempts = [];
  const deny = (moduleName, method) => {
    const original = moduleName[method];
    moduleName[method] = function blockedOutboundNetwork(...args) {
      blockedNetworkAttempts.push(`${method}(${String(args[0] || '').slice(0, 100)})`);
      throw new Error('outbound network is disabled during direct-engine smoke');
    };
    return () => { moduleName[method] = original; };
  };
  const restoreNetwork = [
    deny(http, 'request'), deny(http, 'get'),
    deny(https, 'request'), deny(https, 'get'),
    deny(net, 'connect'), deny(net, 'createConnection'),
  ];
  const originalFetch = globalThis.fetch;
  if (originalFetch) globalThis.fetch = (...args) => {
    blockedNetworkAttempts.push(`fetch(${String(args[0] || '').slice(0, 100)})`);
    throw new Error('outbound network is disabled during direct-engine smoke');
  };
  const ctx = {
    tools, work, inv: null,
    pre: { health: { sentinel: engineIdentity } },
    budget: () => 30_000,
  };
  let result;
  try { result = await sentinel(root, ctx); }
  finally {
    restoreNetwork.reverse().forEach((restore) => restore());
    if (originalFetch) globalThis.fetch = originalFetch;
  }
  if (!result.rawArtifact || !fs.existsSync(result.rawArtifact)) throw new Error('raw Sentinel Cloud output was not persisted');
  const raw = JSON.parse(fs.readFileSync(result.rawArtifact, 'utf8'));
  const normalized = normalizeCloudSignals(root, raw.result.rawAlerts || raw.result.alerts || []);
  return {
    status: result.status,
    rawArtifact: result.rawArtifact,
    rawAlertCount: (raw.result.rawAlerts || raw.result.alerts || []).length,
    normalizedSignalCount: normalized.length,
    actionableSignalCount: normalized.filter((f) => f.signalClass === 'ACTIONABLE_SIGNAL').length,
    signalTypes: normalized.map((f) => f.rule),
    coverage: result.coverage,
    route: buildRoutePlan(normalized),
    blockedNetworkAttempts,
  };
}

async function scanSingleFile(enginePath, source, work, engineIdentity) {
  fs.mkdirSync(work, { recursive: true });
  const engine = require(enginePath);
  const blockedNetworkAttempts = [];
  const deny = (moduleName, method) => {
    const original = moduleName[method];
    moduleName[method] = function blockedOutboundNetwork(...args) {
      blockedNetworkAttempts.push(`${method}(${String(args[0] || '').slice(0, 100)})`);
      throw new Error('outbound network is disabled during direct-engine smoke');
    };
    return () => { moduleName[method] = original; };
  };
  const restore = [deny(http, 'request'), deny(http, 'get'), deny(https, 'request'), deny(https, 'get'), deny(net, 'connect'), deny(net, 'createConnection')];
  const originalFetch = globalThis.fetch;
  if (originalFetch) globalThis.fetch = (...args) => {
    blockedNetworkAttempts.push(`fetch(${String(args[0] || '').slice(0, 100)})`);
    throw new Error('outbound network is disabled during direct-engine smoke');
  };
  let result;
  try {
    result = await engine.scanFile('src/canary.js', source, null, { mode: 'local', profile: 'DEFAULT' });
  } finally {
    restore.reverse().forEach((fn) => fn());
    if (originalFetch) globalThis.fetch = originalFetch;
  }
  const rawArtifact = path.join(work, 'sentinel-scanFile.json');
  fs.writeFileSync(rawArtifact, JSON.stringify({ engine: engineIdentity, entrypoint: 'scanFile', result }, null, 2));
  const alerts = Array.isArray(result.alerts) ? result.alerts : [];
  return {
    entrypoint: 'scanFile', rawArtifact, alertCount: alerts.length,
    signalTypes: alerts.map((a) => a.type),
    blockedNetworkAttempts,
  };
}

async function main() {
  const { tools } = loadConfig();
  const cloud = tools.sentinelCloud;
  const sourceRoot = expand(cloud.repo);
  const enginePath = expand(cloud.engine);
  const workerPath = expand(cloud.worker);
  const bridgePath = expand(cloud.bridge);
  const required = [sourceRoot, enginePath, workerPath, bridgePath].filter((p) => !fs.existsSync(p));
  if (required.length) throw new Error(`Sentinel Cloud source unavailable: ${required.join(', ')}`);
  const gitHeadPath = path.join(sourceRoot, '.git', 'HEAD');
  const gitHead = fs.existsSync(gitHeadPath) ? fs.readFileSync(gitHeadPath, 'utf8').trim() : null;
  const head = gitHead && gitHead.startsWith('ref: ')
    ? fs.readFileSync(path.join(sourceRoot, '.git', gitHead.slice(5)), 'utf8').trim()
    : gitHead;
  const engineId = head
    ? `sentinel-cloud-worker@${head}#sha256:${crypto.createHash('sha256').update(fs.readFileSync(enginePath)).digest('hex')}`
    : null;

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-cloud-static-canaries-'));
  const work = path.join(__dirname, '..', 'out', 'sentinel-cloud-direct-gate');
  const evalRoot = path.join(root, 'eval');
  const bareExecRoot = path.join(root, 'child-process-exec-unbound');
  const execRoot = path.join(root, 'exec');
  const taintRoot = path.join(root, 'existing-taint-fixture');
  for (const target of [evalRoot, bareExecRoot, execRoot, taintRoot]) fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  const evalSource = '// Static canary only. This file is not executed.\nfunction evaluateInput(userInput) { return eval(userInput); }\n';
  const boundExecSource = '// Static canary only. This file is not executed.\nconst child_process = require("child_process");\nfunction run(userInput) { child_process.exec(userInput); }\n';
  const bareExecSource = '// Exact call-only form; intentionally no import/binding; never executed.\nchild_process.exec(userInput);\n';
  const existingTaintSource = '// Static excerpt based on the existing Cloud test fixture; never executed.\n' +
    'const child_process = require("child_process");\n' +
    'const req = { body: { cmd: "dummy" }, query: { cmd: "dummy" } };\n' +
    'function run() { eval(req.body.cmd); child_process.exec("git clone " + req.query.cmd); }\n';
  fs.writeFileSync(path.join(evalRoot, 'src', 'canary.js'), evalSource);
  fs.writeFileSync(path.join(execRoot, 'src', 'canary.js'), boundExecSource);
  fs.writeFileSync(path.join(bareExecRoot, 'src', 'canary.js'), bareExecSource);
  // This reproduces the child_process.exec form already present in the Cloud
  // worker's test_scanner.js taintPayload, without running that test suite.
  fs.writeFileSync(path.join(taintRoot, 'src', 'canary.js'), existingTaintSource);

  try {
  const engineIdentity = {
      repo: sourceRoot, engine: enginePath, engineId, mode: 'local',
      productionParity: 'UNKNOWN',
      resultLabel: 'Sentinel Cloud local engine; production parity unverified',
    };
    const evalResult = await scanStaticFixture(evalRoot, path.join(work, 'eval'), tools, engineIdentity);
    const bareExecResult = await scanStaticFixture(bareExecRoot, path.join(work, 'child-process-exec-unbound'), tools, engineIdentity);
    const execResult = await scanStaticFixture(execRoot, path.join(work, 'child-process-exec'), tools, engineIdentity);
    const existingFixtureResult = await scanStaticFixture(taintRoot, path.join(work, 'cloud-existing-taint-fixture'), tools, engineIdentity);
    const scanFileEval = await scanSingleFile(enginePath, evalSource, path.join(work, 'scanFile-eval'), engineIdentity);
    const scanFileExec = await scanSingleFile(enginePath, bareExecSource, path.join(work, 'scanFile-child-process-exec'), engineIdentity);
    const loadedPurple = Object.keys(require.cache).filter((p) => /sentinel-purple|purple\.js/i.test(p));

    const report = {
      schema: 'sentinel-cloud-direct-gate-smoke/1',
      generatedAt: new Date().toISOString(),
      target: 'temporary local static canaries; fixtures never executed',
      engine: { repo: sourceRoot, engine: enginePath, worker: workerPath, bridge: bridgePath, mode: 'local' },
      engineIdentity,
      canaries: {
        eval: evalResult,
        childProcessExecUnbound: bareExecResult,
        childProcessExecWithRequire: execResult,
        existingCloudTaintFixture: existingFixtureResult,
        scanFileEval,
        scanFileChildProcessExec: scanFileExec,
      },
      purpleModulesLoaded: loadedPurple,
      purpleConfigPresent: Object.prototype.hasOwnProperty.call(tools, 'sentinelPurple'),
      purpleAdapterExported: Object.prototype.hasOwnProperty.call(adapters, 'purple'),
      blockedOutboundNetworkAttempts: [
        ...evalResult.blockedNetworkAttempts,
        ...bareExecResult.blockedNetworkAttempts,
        ...execResult.blockedNetworkAttempts,
        ...existingFixtureResult.blockedNetworkAttempts,
        ...scanFileEval.blockedNetworkAttempts,
        ...scanFileExec.blockedNetworkAttempts,
      ],
    };
    fs.writeFileSync(path.join(work, 'smoke-summary.json'), JSON.stringify(report, null, 2));

    if (evalResult.status !== 'PARTIAL') throw new Error(`expected PARTIAL while coverage is unmeasured; got ${evalResult.status}`);
    if (evalResult.coverage.engineCoverage !== 'ENGINE_COVERAGE_UNMEASURED') throw new Error('engine coverage was not marked unmeasured');
    if (evalResult.route.decision !== 'AMPLIFY' || !evalResult.route.tools.includes('codeql') || !evalResult.route.tools.includes('semgrep')) {
      throw new Error(`known JS eval canary did not route to CodeQL+Semgrep: ${JSON.stringify(evalResult.route)}`);
    }
    if (evalResult.route.tools.some((t) => ['trivy', 'osv', 'bandit', 'shellcheck'].includes(t))) {
      throw new Error(`JS process-execution signal routed unrelated specialists: ${evalResult.route.tools.join(',')}`);
    }
    if (loadedPurple.length) throw new Error(`Purple modules entered the process: ${loadedPurple.join(', ')}`);
    if (report.purpleConfigPresent || report.purpleAdapterExported) throw new Error('Purple remains wired into active config or adapter exports');
    if (report.blockedOutboundNetworkAttempts.length) throw new Error(`Cloud scanner attempted outbound network: ${report.blockedOutboundNetworkAttempts.join(', ')}`);
    console.log(JSON.stringify(report, null, 2));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
