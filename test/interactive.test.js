'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { interactiveArgs, handlePRWorkflow } = require('../workflow/interactive');

function scriptedIO(answers) {
  const output = { text: '', write(value) { this.text += value; } };
  return { output, async question() { return answers.shift() ?? ''; } };
}

test('guided flow builds a pinned preflight command', async () => {
  const sha = 'a'.repeat(40);
  assert.deepEqual(await interactiveArgs(scriptedIO(['5', 'C:/repo', sha])), ['preflight', 'C:/repo', '--commit', sha]);
});

test('guided flow asks for confirmation before returning a run command', async () => {
  const sha = 'b'.repeat(40);
  assert.deepEqual(await interactiveArgs(scriptedIO(['4', 'C:/repo', sha, 'repo', 'yes'])), ['run', 'C:/repo', '--commit', sha, '--routing', 'repo']);
  assert.equal(await interactiveArgs(scriptedIO(['4', 'C:/repo', sha, 'file', 'no'])), null);
});

test('guided flow rejects incomplete commit identities and invalid scopes', async () => {
  await assert.rejects(interactiveArgs(scriptedIO(['5', 'C:/repo', 'abc'])), /40 caracteres/);
  const sha = 'c'.repeat(40);
  await assert.rejects(interactiveArgs(scriptedIO(['4', 'C:/repo', sha, 'branch'])), /Scope must/);
});

test('PR workflow honors Cloud Pulse selection and does not fall back to local Lite', async () => {
  const sha = 'd'.repeat(40);
  const io = scriptedIO(['', '17', '2', '1']);
  let cloudInput;
  const progressEvents = [];
  await handlePRWorkflow(io, {
    checkGitHubSession: () => ({ authenticated: true, account: 'test', method: 'gh_cli' }),
    defaultRepo: 'acme/app',
    execFileSync: (_bin, args) => {
      assert.deepEqual(args.slice(0, 3), ['pr', 'list', '--repo']);
      return JSON.stringify([{ number: 17, title: 'Test PR', author: { login: 'octocat' }, headRefOid: sha }]);
    },
    cloudKeys: {
      listKeys: () => [{ index: 1, maskedToken: 'sent••••key' }],
      getKey: () => ({ token: 'sentinel-secret', name: 'Test Cloud Key' }),
    },
    fetchCloudPRScan: async (input) => {
      cloudInput = input;
      input.onProgress({ stage: 'AUTH', state: 'COMPLETE', detail: 'plan Team' });
      input.onProgress({ stage: 'ENGINE', state: 'RUNNING', detail: 'full PR scan' });
      input.onProgress({ stage: 'ENGINE', state: 'COMPLETE', detail: 'engine 5.0' });
      return {
        level1: { status: 'FLAG', score: 38, filesAnalyzed: 4 },
        level3: { samples: [{ severity: 'HIGH', title: 'Risk signal', file: 'src/app.js', line: 4, description: 'Signal description' }] },
        engine_version: '5.0',
      };
    },
    createPRProgress: () => ({ update: (event) => progressEvents.push(event), finish: () => {} }),
    liteScanner: { auditPRDiff: () => { throw new Error('Cloud choice must not use Lite'); }, exportToMarkdown: () => ({ fullPath: 'report.md', bytes: 1 }) },
  });

  assert.equal(cloudInput.repo, 'acme/app');
  assert.equal(cloudInput.prNumber, 17);
  assert.equal(cloudInput.expectedHeadSha, sha);
  assert.equal(cloudInput.token, 'sentinel-secret');
  assert.equal(io.output.text.includes('Sentinel Cloud 5.0; análisis completo del PR'), true);
  assert.equal(io.output.text.includes('FLAG'), true);
  assert.equal(io.output.text.includes('Risk signal'), true);
  assert.match(io.output.text, /MUESTRAS DE EVIDENCIA/);
  assert.equal(progressEvents.some((event) => event.stage === 'RESULT' && event.state === 'COMPLETE'), true);
});

test('PR workflow keeps Lite local and reports the selected local path', async () => {
  const sha = 'e'.repeat(40);
  const io = scriptedIO(['', '17', '1', '1']);
  const calls = [];
  let resultInput;
  let progressOptions;
  await handlePRWorkflow(io, {
    checkGitHubSession: () => ({ authenticated: true, account: 'test', method: 'gh_cli' }),
    defaultRepo: 'acme/app',
    execFileSync: (_bin, args) => {
      calls.push(args);
      if (args[1] === 'list') return JSON.stringify([{ number: 17, title: 'Test PR', author: { login: 'octocat' }, headRefOid: sha }]);
      if (args[1] === 'view') return JSON.stringify({ headRefOid: sha });
      if (args[1] === 'diff') return 'diff --git a/example.js b/example.js';
      throw new Error('unexpected gh command');
    },
    cloudKeys: { listKeys: () => [], getKey: () => null },
    fetchCloudPRScan: async () => { throw new Error('Lite must not call Cloud'); },
    createPRProgress: (options) => {
      progressOptions = options;
      return { update: () => {}, finish: () => {} };
    },
    liteScanner: {
      auditPRDiff: (diff, metadata) => {
        resultInput = { diff, metadata };
        return { verdict: 'PASS', riskScore: 0, counts: { critical: 0, high: 0, medium: 0, low: 0 }, findings: [] };
      },
      exportToMarkdown: () => ({ fullPath: 'report.md', bytes: 1 }),
    },
  });

  assert.equal(resultInput.diff, 'diff --git a/example.js b/example.js');
  assert.equal(resultInput.metadata.repo, 'acme/app');
  assert.deepEqual(calls.filter((args) => args[1] === 'view').length, 2);
  assert.equal(progressOptions.engineLabel, 'Sentinel Lite local');
  assert.match(progressOptions.note, /no se solicitó un Pulso/);
  assert.match(io.output.text, /Sentinel Lite local/);
});
