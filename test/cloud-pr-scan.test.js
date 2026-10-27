'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { fetchCloudPRScan, resolvedBaseUrl } = require('../lib/cloud-pr-scan');

const sha = 'a'.repeat(40);
const scan = { level1: { status: 'DEGRADED', score: 12, filesAnalyzed: 2 }, level3: { samples: [] }, engine_version: 'test-engine' };

test('accepts HTTPS Cloud URLs and local loopback only', () => {
  assert.equal(resolvedBaseUrl({ SENTINEL_CLOUD_URL: 'https://cloud.example///' }), 'https://cloud.example');
  assert.equal(resolvedBaseUrl({ SENTINEL_CLOUD_URL: 'http://127.0.0.1:3000/' }), 'http://127.0.0.1:3000');
  assert.throws(() => resolvedBaseUrl({ SENTINEL_CLOUD_URL: 'http://cloud.example' }), /HTTPS/);
});

test('validates scan capability, pins the PR SHA, and sends the Sentinel token only to Cloud', async () => {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({ url, init });
    return requests.length === 1
      ? new Response(JSON.stringify({ planLabel: 'Team', capabilities: { remote_scan: true } }), { status: 200 })
      : new Response(JSON.stringify(scan), { status: 200 });
  };
  const progress = [];
  const result = await fetchCloudPRScan({
    repo: 'acme/app', prNumber: 17, expectedHeadSha: sha, token: 'sentinel-secret',
    baseUrl: 'https://cloud.example', fetchImpl, onProgress: (event) => progress.push(event),
  });

  assert.equal(result.level1.status, 'DEGRADED');
  assert.equal(requests[0].url, 'https://cloud.example/api/auth/capabilities');
  assert.equal(requests[1].url, 'https://cloud.example/api/scan/pr');
  assert.equal(requests[1].init.headers.Authorization, 'Bearer sentinel-secret');
  assert.deepEqual(JSON.parse(requests[1].init.body), { repo: 'acme/app', prNumber: 17, expectedHeadSha: sha });
  assert.deepEqual(progress.map((event) => `${event.stage}:${event.state}`), ['AUTH:COMPLETE', 'ENGINE:RUNNING', 'ENGINE:COMPLETE']);
});

test('does not call the PR scan endpoint when the key lacks remote_scan', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    return new Response(JSON.stringify({ capabilities: { remote_scan: false } }), { status: 200 });
  };
  await assert.rejects(fetchCloudPRScan({ repo: 'acme/app', prNumber: 1, expectedHeadSha: sha, token: 'sentinel-secret', baseUrl: 'https://cloud.example', fetchImpl }), /no tiene habilitados/);
  assert.equal(calls, 1);
});

test('rejects a changed PR head and redacts the bearer token from API errors', async () => {
  const fetchImpl = async (_url, init) => init.method === 'POST'
    ? new Response(JSON.stringify({ error: 'rejected sentinel-secret' }), { status: 409 })
    : new Response(JSON.stringify({ capabilities: { remote_scan: true } }), { status: 200 });
  await assert.rejects(fetchCloudPRScan({ repo: 'acme/app', prNumber: 1, expectedHeadSha: sha, token: 'sentinel-secret', baseUrl: 'https://cloud.example', fetchImpl }), /rejected \[redacted\]/);
});
