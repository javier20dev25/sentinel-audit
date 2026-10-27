'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { interactiveArgs, safeTerminal } = require('../workflow/interactive');
const { parse } = require('../audit-runner');

function scriptedIO(answers) {
  const output = { text: '', write(value) { this.text += value; } };
  return { output, async question() { return answers.shift() ?? ''; } };
}

test('running the executable without a command opens the interactive menu', () => {
  assert.equal(parse(['node', 'audit-runner.js']).command, 'interactive');
  assert.equal(parse(['node', 'audit-runner.js', 'doctor']).command, 'doctor');
});

test('interactive menu shows the GitHub identity and keeps the disclaimer opt-in', async () => {
  const io = scriptedIO(['8']);
  assert.equal(await interactiveArgs(io), null);
  assert.match(io.output.text, /SENTINEL AUDIT/);
  assert.match(io.output.text, /GitHub:/);
  assert.match(io.output.text, /7\) Leer aviso de responsabilidad/);
  assert.doesNotMatch(io.output.text, /El usuario es el único responsable/);
  assert.doesNotMatch(io.output.text, /[\u{1F300}-\u{1FAFF}]/u);
});

test('terminal output strips control sequences from repository evidence', () => {
  assert.equal(safeTerminal('safe\u001b[2J\u001b]0;owned\u0007\u0007text'), 'safe text');
});

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
  await assert.rejects(interactiveArgs(scriptedIO(['4', 'C:/repo', sha, 'branch'])), /Alcance debe ser/);
});
