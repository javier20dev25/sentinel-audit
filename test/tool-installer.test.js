'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const installer = require('../web/tool-installer');

test('installer only accepts the curated specialist list', () => {
  assert.deepEqual(new Set(installer.supportedTools()), new Set(['codeql','semgrep','trivy','osv','bandit','shellcheck']));
  assert.throws(() => installer.startInstall('unknown'), /no permitida/);
});

test('CodeQL terms must be acknowledged before any download starts', () => {
  assert.throws(() => installer.startInstall('codeql'), /acepta las condiciones/);
});
