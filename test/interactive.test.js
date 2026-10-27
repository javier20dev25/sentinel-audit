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

test('key management returns to the main menu without terminating the CLI', async () => {
  const io = scriptedIO(['2', '0', '8']);
  assert.equal(await interactiveArgs(io), null);
  assert.match(io.output.text, /GESTIÓN DE CLAVES DE SENTINEL CLOUD/);
  assert.match(io.output.text, /0\) Volver al menú principal/);
  assert.equal((io.output.text.match(/Selecciona una opción:/g) || []).length, 2);
});

test('empty menu input exits cleanly instead of throwing or re-entering a broken form', async () => {
  const io = scriptedIO(['']);
  assert.equal(await interactiveArgs(io), null);
  assert.match(io.output.text, /8\) Salir/);
});

test('pinned workflow options advertise GitHub repo and commit pickers', async () => {
  const io = scriptedIO(['8']);
  await interactiveArgs(io);
  assert.match(io.output.text, /Elegir repo y commit de GitHub y ejecutar auditoría/);
  assert.match(io.output.text, /Elegir repo y commit de GitHub para preflight/);
  assert.doesNotMatch(io.output.text, /Ruta del repositorio:/);
  assert.doesNotMatch(io.output.text, /SHA completo de 40 caracteres:/);
});
