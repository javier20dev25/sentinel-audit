'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startWebDashboard } = require('../web/server');

test('selecting a repository brings its PR inventory into view', () => {
  const app = fs.readFileSync(path.join(__dirname, '../web/public/app.js'), 'utf8');
  const loadPulls = app.slice(app.indexOf('async function loadPulls'), app.indexOf('async function refreshCloud'));
  assert.match(loadPulls, /scrollIntoView/);
});

test('repository cards expose keyboard activation', () => {
  const app = fs.readFileSync(path.join(__dirname, '../web/public/app.js'), 'utf8');
  assert.match(app, /data-repo[\s\S]{0,500}keydown/);
});

test('PR inventory exposes repo badges, severity composition, no-findings state and GitHub evidence actions', () => {
  const app = fs.readFileSync(path.join(__dirname, '../web/public/app.js'), 'utf8');
  assert.match(app, /repo-pr-badge/);
  assert.match(app, /function prSeverityPanel/);
  assert.match(app, /severityDonut/);
  assert.match(app, /no-findings-card/);
  assert.match(app, /function githubEvidenceLink/);
  assert.match(app, /data-pending-scan/);
});

test('signal nature classifier separates malicious indicators from security defects', () => {
  const app = fs.readFileSync(path.join(__dirname, '../web/public/app.js'), 'utf8');
  const source = app.slice(app.indexOf('const SIGNAL_NATURE'), app.indexOf('function renderSignalFlow'));
  const { classifySignalNature } = new Function(`${source}; return { classifySignalNature };`)();
  assert.equal(classifySignalNature({ title: 'Obfuscated payload executed via child_process' }).id, 'malicious');
  assert.equal(classifySignalNature({ title: 'SQL injection in query builder', category: 'injection' }).id, 'defect');
  assert.equal(classifySignalNature({ title: 'Unexpected dependency metadata' }).id, 'unclassified');
});

test('local web dashboard serves UI, reports GitHub identity, and rejects unauthenticated writes', async (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-dashboard-test-'));
  const server = await startWebDashboard({ port: 0, databasePath: path.join(temp, 'audit.sqlite') });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const page = await fetch(base);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Sentinel <em>Audit/);
  assert.match(page.headers.get('content-security-policy'), /default-src 'self'/);
  assert.match(page.headers.get('content-security-policy'), /style-src 'self' 'unsafe-inline'/);
  const [theme, logo] = await Promise.all([fetch(`${base}/theme.css`), fetch(`${base}/sentinel-logo.svg`)]);
  assert.equal(theme.status, 200);
  const themeText = await theme.text();
  assert.match(themeText, /color-scheme:\s*dark/);
  assert.match(themeText, /@keyframes scanSweep/);
  assert.equal(logo.headers.get('content-type'), 'image/svg+xml');
  assert.match(await logo.text(), /#e6432b/);

  const state = await fetch(`${base}/api/state`).then((response) => response.json());
  assert.equal(state.github.authenticated, true);
  assert.equal(state.github.account, 'javier20dev25');
  assert.ok(Array.isArray(state.tools));
  assert.ok(state.tools.every((tool) => typeof tool.installed === 'boolean'));
  assert.ok(state.database.endsWith('audit.sqlite'));
  const jobs = await fetch(`${base}/api/tools/jobs`).then((response) => response.json());
  assert.deepEqual(jobs.jobs, []);
  const script = await fetch(`${base}/app.js`).then((response) => response.text());
  assert.match(script, /Descargar e instalar/);
  assert.match(script, /live-route-node/);
  assert.match(themeText, /@keyframes routeEnter/);

  const rejected = await fetch(`${base}/api/scans`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://attacker.example', 'x-sentinel-audit-request': 'ui' },
    body: JSON.stringify({ repo: 'javier20dev25/Merx', prNumber: 12, mode: 'lite' }),
  });
  assert.equal(rejected.status, 403);
});
