'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const settings = require('../lib/cloud-settings');

test('Pulse resolves the public production endpoint when none is configured', () => {
  assert.equal(settings.DEFAULT_ENDPOINT, 'https://sentinel-psi-nine.vercel.app');
  assert.equal(settings.resolveEndpoint({ url: '', env: '' }), settings.DEFAULT_ENDPOINT);
});

test('explicit and environment endpoints take precedence over the default', () => {
  assert.equal(settings.resolveEndpoint({ url: 'https://audit.example.test', env: 'https://env.example.test' }), 'https://audit.example.test');
  assert.equal(settings.resolveEndpoint({ url: '', env: 'https://env.example.test' }), 'https://env.example.test');
});

test('endpoint validation rejects plaintext remote URLs and credentials', () => {
  assert.throws(() => settings.resolveEndpoint({ url: 'http://example.test', env: '' }), /HTTPS/);
  assert.throws(() => settings.resolveEndpoint({ url: 'https://user:pass@example.test', env: '' }), /credenciales/);
  assert.throws(() => settings.resolveEndpoint({ url: 'https://example.test/?token=1', env: '' }), /credenciales/);
});
