'use strict';

// Sentinel Audit's local dashboard. It binds only to loopback and invokes the
// same pinned-commit pipeline as the CLI; the browser never receives API tokens.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const keys = require('../lib/cloud-keys');
const liteScanner = require('../lib/lite-scanner');
const { runAuditV1, continueSpecialists } = require('../workflow/pipeline-v1');
const { checkGitHubSession } = require('../workflow/interactive');
const { loadConfig } = require('../lib/core');
const { checkToolHealth } = require('../workflow/preflight');
const { resolveClient } = require('../adapters/hosted');
const toolInstaller = require('./tool-installer');

const PUBLIC = path.join(__dirname, 'public');
const DATA = path.join(os.homedir(), '.sentinel-audit');
const DB_PATH = path.join(DATA, 'audit.sqlite');
const MAX_BODY = 1024 * 1024;
const SCANS = new Map();

function database(filePath = DB_PATH) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  try { fs.chmodSync(path.dirname(filePath), 0o700); } catch (_) {}
  const db = new DatabaseSync(filePath);
  db.exec(`PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY, repo TEXT NOT NULL, pr_number INTEGER NOT NULL,
      head_sha TEXT NOT NULL, mode TEXT NOT NULL, verdict TEXT,
      risk_score INTEGER, finding_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
      body_sha256 TEXT, diff_sha256 TEXT, body_json TEXT, error TEXT
    );
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      source TEXT NOT NULL, severity TEXT, category TEXT, title TEXT,
      file TEXT, line INTEGER, evidence TEXT
    );
    CREATE TABLE IF NOT EXISTS stages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      stage TEXT NOT NULL, state TEXT NOT NULL, detail TEXT, at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS stages_scan_idx ON stages(scan_id);
  `);
  const migrateFinding = db.prepare('UPDATE findings SET severity=?,file=? WHERE id=?');
  for (const row of db.prepare('SELECT id,severity,file,evidence FROM findings').all()) {
    let evidence = {};
    try { evidence = JSON.parse(row.evidence || '{}'); } catch (_) {}
    const severity = normalizedSeverity(row.severity == null ? (evidence.severity == null && evidence.rawEngineSignal ? evidence.rawEngineSignal.severity : evidence.severity) : row.severity);
    const file = evidencePath(row.file);
    if (severity !== row.severity || file !== row.file) migrateFinding.run(severity, file, row.id);
  }
  try { fs.chmodSync(filePath, 0o600); } catch (_) {}
  return db;
}

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000, windowsHide: true });
}

function cloudStatus() {
  const { tools, policies } = loadConfig();
  const entries = keys.listKeys();
  const client = resolveClient({ tools }, {});
  const url = process.env.SENTINEL_CLOUD_URL || null;
  const enabled = !!(policies.hosted && policies.hosted.enabled);
  const reasons = [];
  if (!enabled) reasons.push('La política de Sentinel Audit tiene Cloud desactivado.');
  if (!client) reasons.push('No se encuentra @sentinel/cloud-client.');
  if (!url) reasons.push('Falta SENTINEL_CLOUD_URL.');
  if (!entries.length) reasons.push('No hay claves de Sentinel Cloud guardadas.');
  return { enabled: enabled && !!client && !!url && entries.length > 0, reasons, keys: entries, urlConfigured: !!url, clientAvailable: !!client };
}

function state() {
  const { tools, policies } = loadConfig();
  const github = checkGitHubSession();
  const health = checkToolHealth(tools);
  const specialistTools = Object.entries(health).filter(([name]) => name !== 'sentinel').map(([name, item]) => ({ name, available: !!item.available, state: item.state, reason: item.reason || null }));
  const localEngine = health.sentinel || { available: false, state: 'UNAVAILABLE', reason: 'No se detectó el motor local Sentinel Cloud.' };
  return { github, currentRepo: detectCurrentRepo(), tools: [{ name: 'Sentinel Lite', available: true, installed: true, state: 'AVAILABLE' }, { name: 'Sentinel local', available: !!localEngine.available, installed: !!localEngine.available, state: localEngine.state || (localEngine.available ? 'AVAILABLE' : 'UNAVAILABLE'), reason: localEngine.reason || null }, ...specialistTools.map((tool) => { const detail = health[tool.name] || {}; return { ...tool, installed: !!detail.path, blockedByHost: !!detail.blockedByHost, path: detail.path || null, reason: detail.blockedByHost ? `Encontrado en ${detail.path}; el runtime guard bloquea su ejecución en este proceso.` : detail.reason || null }; })], cloud: cloudStatus(), policies: { hostedEnabled: !!(policies.hosted && policies.hosted.enabled) }, database: DB_PATH };
}

function detectCurrentRepo() {
  try {
    const value = execFileSync('git', ['remote', 'get-url', 'origin'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).trim();
    const m = value.match(/(?:github\.com[:/])([\w.-]+\/[\w.-]+?)(?:\.git)?$/i);
    return m ? m[1] : null;
  } catch (_) { return null; }
}

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(body);
}

function safeError(error) { return String(error && error.message || error).replace(/(?:sntl_[A-Za-z0-9_-]{8,}|Bearer\s+\S+)/gi, '[redacted]').slice(0, 1000); }
function normalizedSeverity(value) {
  const numeric = typeof value === 'number' || (typeof value === 'string' && /^\d+$/.test(value)) ? Number(value) : null;
  if (numeric !== null) return ({ 5: 'CRITICAL', 4: 'HIGH', 3: 'MEDIUM', 2: 'LOW', 1: 'INFO' })[numeric] || 'INFO';
  return value == null ? 'UNSPECIFIED' : String(value).toUpperCase();
}
function evidencePath(value) {
  if (typeof value !== 'string' || !value) return null;
  const match = value.match(/[\\/]worktree[\\/](.+)$/i);
  if (match) return match[1].replace(/\\/g, '/');
  return path.isAbsolute(value) ? path.basename(value) : value.replace(/\\/g, '/');
}

async function readBody(req) {
  const chunks = []; let size = 0;
  for await (const part of req) {
    size += part.length;
    if (size > MAX_BODY) throw new Error('La solicitud excede el límite permitido.');
    chunks.push(part);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

function assertLocal(req) {
  const host = String(req.headers.host || '').split(':')[0].replace(/^\[|\]$/g, '').toLowerCase();
  if (!['127.0.0.1', 'localhost', '::1'].includes(host)) throw Object.assign(new Error('Solo se aceptan solicitudes locales.'), { status: 403 });
  if (req.method !== 'GET') {
    const origin = req.headers.origin;
    if (!origin || !/^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/i.test(origin) || req.headers['x-sentinel-audit-request'] !== 'ui') {
      throw Object.assign(new Error('Origen no autorizado.'), { status: 403 });
    }
  }
}

function recordStage(db, scanId, stage, status, detail) {
  db.prepare('INSERT INTO stages(scan_id,stage,state,detail,at) VALUES(?,?,?,?,?)').run(scanId, stage, status, typeof detail === 'string' ? detail : detail ? JSON.stringify(detail) : null, new Date().toISOString());
  const item = SCANS.get(scanId);
  if (item) item.events.push({ stage, state: status, detail: detail || null, at: new Date().toISOString() });
}

async function startScan(db, payload) {
  const repo = String(payload.repo || '');
  const number = Number(payload.prNumber);
  const mode = payload.mode === 'pulse' ? 'pulse' : 'lite';
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || !Number.isSafeInteger(number) || number < 1) throw new Error('Repositorio o número de PR inválido.');
  const cloud = cloudStatus();
  if (mode === 'pulse' && !cloud.enabled) throw new Error(`Pulse no está disponible: ${cloud.reasons.join(' ')}`);
  const id = `web-${crypto.randomUUID()}`;
  const startedAt = new Date().toISOString();
  db.prepare(`INSERT INTO scans(id,repo,pr_number,head_sha,mode,status,started_at) VALUES(?,?,?,?,?,'RUNNING',?)`).run(id, repo, number, 'PENDING', mode, startedAt);
  SCANS.set(id, { events: [], state: 'RUNNING', result: null });
  setImmediate(async () => {
    let checkout = null;
    try {
      recordStage(db, id, 'PR_METADATA', 'RUNNING', `Consultando ${repo}#${number}`);
      const meta = JSON.parse(gh(['pr', 'view', String(number), '--repo', repo, '--json', 'headRefOid,title,author,url,baseRefName,headRefName']));
      if (!/^[a-f0-9]{40}$/i.test(meta.headRefOid || '')) throw new Error('GitHub no devolvió el SHA completo del head del PR.');
      recordStage(db, id, 'PR_METADATA', 'COMPLETE', { commit: meta.headRefOid, title: meta.title, url: meta.url });
      const diff = gh(['pr', 'diff', String(number), '--repo', repo]);
      const diffHash = crypto.createHash('sha256').update(diff).digest('hex');
      recordStage(db, id, 'DIFF_PIN', 'COMPLETE', { sha256: diffHash, bytes: Buffer.byteLength(diff) });
      const lite = liteScanner.auditPRDiff(diff, { repo, prNumber: number, author: meta.author && meta.author.login || 'unknown' });
      recordStage(db, id, 'SENTINEL_LITE', 'COMPLETE', { findings: lite.findings.length, sha256: lite.contentHash });
      const key = mode === 'pulse' ? keys.getKey(payload.keyId || 1) : null;
      if (mode === 'pulse' && !key) throw new Error('La clave seleccionada ya no existe.');
      checkout = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-web-'));
      const source = path.join(checkout, 'source');
      execFileSync('git', ['clone', '--quiet', '--no-checkout', `https://github.com/${repo}.git`, source], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000, windowsHide: true });
      execFileSync('git', ['-C', source, 'fetch', '--quiet', '--depth=1', 'origin', `refs/pull/${number}/head`], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000, windowsHide: true });
      execFileSync('git', ['-C', source, 'checkout', '--quiet', '--detach', meta.headRefOid], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000, windowsHide: true });
      const seedFindings = lite.findings.map((f) => ({ type: f.ruleId || f.rule || f.title, title: f.title, description: f.description, message: f.title, snippet: f.snippet || null, file: f.file, line: Number.isInteger(f.line) && f.line > 0 ? f.line : null, severity: ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2 })[String(f.severity).toUpperCase()] || 1, evidence: [f.ruleId || f.rule || f.title].filter(Boolean) }));
      const pipelineOptions = { name: `${repo.replace('/', '-')}-pr-${number}`, commit: meta.headRefOid, routing: 'file', onProgress: (event) => recordStage(db, id, event.stage, event.state, event.detail) };
      if (mode === 'pulse') Object.assign(pipelineOptions, { provider: 'cloud', apiToken: key.token, apiUrl: process.env.SENTINEL_CLOUD_URL });
      else Object.assign(pipelineOptions, { seedFindings, seedEngine: 'Sentinel Audit Lite PR diff' });
      const result = await runAuditV1(source, pipelineOptions);
      recordStage(db, id, 'PIPELINE_COMPLETE', 'COMPLETE', { verdict: result.expediente.auditVerdict && result.expediente.auditVerdict.verdict, executionDir: result.executionDir });
      const body = { schema: 'sentinel-audit-web-scan/1.0', id, repository: repo, pullRequest: { number, title: meta.title, url: meta.url, author: meta.author && meta.author.login || null, base: meta.baseRefName, head: meta.headRefName, commit: meta.headRefOid }, mode, createdAt: startedAt, diff: { sha256: diffHash, bytes: Buffer.byteLength(diff), files: lite.filesAnalyzed }, lite, audit: result.expediente, executionDir: result.executionDir, stageTimeline: SCANS.get(id).events };
      const canonical = JSON.stringify(body);
      const bodyHash = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
      body.integrity = { algorithm: 'SHA-256', bodyHash, diffHash };
      const serialized = JSON.stringify(body);
      const findings = [...(lite.findings || []).map((f) => ({ source: 'sentinel-lite', ...f })), ...Object.entries(result.expediente.tools || {}).flatMap(([sourceName, item]) => (item.findings || []).map((f) => ({ source: sourceName, ...f })))];
      db.prepare(`UPDATE scans SET head_sha=?,verdict=?,risk_score=?,finding_count=?,status='COMPLETE',finished_at=?,body_sha256=?,diff_sha256=?,body_json=? WHERE id=?`).run(meta.headRefOid, result.expediente.auditVerdict && result.expediente.auditVerdict.verdict || lite.verdict, lite.riskScore, findings.length, new Date().toISOString(), bodyHash, diffHash, serialized, id);
      const addFinding = db.prepare('INSERT INTO findings(scan_id,source,severity,category,title,file,line,evidence) VALUES(?,?,?,?,?,?,?,?)');
      for (const f of findings) addFinding.run(id, f.source || 'unknown', normalizedSeverity(f.severity == null && f.rawEngineSignal ? f.rawEngineSignal.severity : f.severity), f.category || null, f.title || f.message || f.type || 'Finding', evidencePath(f.file), Number.isInteger(f.line) ? f.line : null, JSON.stringify(f));
      SCANS.get(id).state = 'COMPLETE'; SCANS.get(id).result = body;
    } catch (error) {
      recordStage(db, id, 'FAILED', 'FAILED', safeError(error));
      db.prepare("UPDATE scans SET status='FAILED',finished_at=?,error=? WHERE id=?").run(new Date().toISOString(), safeError(error), id);
      SCANS.get(id).state = 'FAILED'; SCANS.get(id).error = safeError(error);
    } finally { if (checkout) try { fs.rmSync(checkout, { recursive: true, force: true }); } catch (_) {} }
  });
  return { id, state: 'RUNNING' };
}

function handle(req, res, db) {
  assertLocal(req);
  const url = new URL(req.url, 'http://127.0.0.1');
  const method = req.method;
  const route = url.pathname;
  if (method === 'GET' && route === '/api/state') return json(res, 200, state());
  if (method === 'GET' && route === '/api/tools/jobs') return json(res, 200, { jobs: toolInstaller.listJobs() });
  if (method === 'POST' && route === '/api/tools/install') return readBody(req).then((body) => json(res, 202, toolInstaller.startInstall(String(body.tool || ''), { acceptLicenseTerms: body.acceptLicenseTerms === true })));
  const toolJobMatch = route.match(/^\/api\/tools\/jobs\/([\w-]+)$/);
  if (method === 'GET' && toolJobMatch) {
    const job = toolInstaller.getJob(toolJobMatch[1]);
    return job ? json(res, 200, job) : json(res, 404, { error: 'Trabajo de instalación no encontrado.' });
  }
  if (method === 'GET' && route === '/api/repos') {
    const ghState = checkGitHubSession();
    if (!ghState.authenticated || ghState.account === 'Environment Token') return json(res, 200, { repositories: [], reason: 'La sesión gh CLI no está disponible para enumerar repositorios.' });
    return json(res, 200, { repositories: JSON.parse(gh(['repo', 'list', ghState.account, '--json', 'nameWithOwner,description,isPrivate', '--limit', '100'])) });
  }
  const prMatch = route.match(/^\/api\/repos\/([\w.-]+)\/([\w.-]+)\/pulls$/);
  if (method === 'GET' && prMatch) {
    const repo = `${prMatch[1]}/${prMatch[2]}`;
    return json(res, 200, { pullRequests: JSON.parse(gh(['pr', 'list', '--repo', repo, '--json', 'number,title,author,headRefName,headRefOid,updatedAt,url', '--limit', '50'])) });
  }
  if (method === 'GET' && route === '/api/scans') return json(res, 200, { scans: db.prepare('SELECT id,repo,pr_number,head_sha,mode,verdict,risk_score,finding_count,status,started_at,finished_at,body_sha256,diff_sha256,error FROM scans ORDER BY started_at DESC LIMIT 200').all() });
  if (method === 'GET' && route === '/api/analytics') {
    return json(res, 200, { severities: db.prepare('SELECT severity,COUNT(*) count FROM findings GROUP BY severity ORDER BY count DESC').all(), sources: db.prepare('SELECT source,COUNT(*) count FROM findings GROUP BY source ORDER BY count DESC').all(), files: db.prepare('SELECT file,COUNT(*) count FROM findings WHERE file IS NOT NULL GROUP BY file ORDER BY count DESC LIMIT 12').all(), timeline: db.prepare("SELECT substr(started_at,1,10) day,COUNT(*) count FROM scans GROUP BY day ORDER BY day").all(), categories: db.prepare('SELECT category,COUNT(*) count FROM findings GROUP BY category ORDER BY count DESC').all() });
  }
  if (method === 'GET' && route === '/api/database') {
    const allowed = { scans: 'scans', findings: 'findings', stages: 'stages' };
    const table = url.searchParams.get('table') || 'scans';
    if (!allowed[table]) return json(res, 400, { error: 'Tabla no permitida.' });
    const rows = db.prepare(`SELECT * FROM ${allowed[table]} ORDER BY 1 DESC LIMIT 250`).all();
    return json(res, 200, { table, rows });
  }
  const scanMatch = route.match(/^\/api\/scans\/([\w-]+)$/);
  if (method === 'GET' && scanMatch) {
    const id = scanMatch[1]; const row = db.prepare('SELECT * FROM scans WHERE id=?').get(id);
    if (!row) return json(res, 404, { error: 'Scan no encontrado.' });
    const live = SCANS.get(id);
    return json(res, 200, { id, status: row.status, error: row.error, events: live ? live.events : db.prepare('SELECT stage,state,detail,at FROM stages WHERE scan_id=? ORDER BY id').all(id), result: row.body_json ? JSON.parse(row.body_json) : null });
  }
  if (method === 'POST' && route === '/api/scans') return readBody(req).then((body) => startScan(db, body)).then((v) => json(res, 202, v));
  if (method === 'POST' && route === '/api/keys') return readBody(req).then((body) => json(res, 201, keys.addKey(String(body.token || ''), String(body.name || ''))));
  const keyMatch = route.match(/^\/api\/keys\/([\w-]+)$/);
  if (method === 'DELETE' && keyMatch) { const removed = keys.revokeKey(keyMatch[1]); return json(res, 200, { removed: removed.removed.id, warning: removed.warning }); }
  const extendMatch = route.match(/^\/api\/scans\/([\w-]+)\/extend$/);
  if (method === 'POST' && extendMatch) return readBody(req).then(async (body) => {
    const scan = db.prepare('SELECT * FROM scans WHERE id=?').get(extendMatch[1]);
    if (!scan || !scan.body_json) throw Object.assign(new Error('El expediente no está disponible para ampliar.'), { status: 404 });
    const document = JSON.parse(scan.body_json); const executionDir = document.executionDir;
    const outcome = await continueSpecialists(executionDir, { only: Array.isArray(body.tools) ? body.tools : [] });
    const updated = { ...document, audit: outcome.expediente, stageTimeline: [...(document.stageTimeline || []), { stage: 'SPECIALIST_EXTENSION', state: 'COMPLETE', detail: body.tools || [] }] };
    const unhashed = { ...updated }; delete unhashed.integrity;
    const plain = JSON.stringify(unhashed); const bodyHash = crypto.createHash('sha256').update(plain).digest('hex');
    updated.integrity = { algorithm: 'SHA-256', bodyHash, diffHash: document.diff.sha256 };
    const serialized = JSON.stringify(updated);
    db.exec('BEGIN');
    try {
      db.prepare("DELETE FROM findings WHERE scan_id=? AND source<>'sentinel-lite'").run(scan.id);
      const addFinding = db.prepare('INSERT INTO findings(scan_id,source,severity,category,title,file,line,evidence) VALUES(?,?,?,?,?,?,?,?)');
      for (const [sourceName, item] of Object.entries(outcome.expediente.tools || {})) for (const finding of item.findings || []) {
        addFinding.run(scan.id, sourceName, normalizedSeverity(finding.severity == null && finding.rawEngineSignal ? finding.rawEngineSignal.severity : finding.severity), finding.category || null, finding.title || finding.message || finding.type || 'Finding', evidencePath(finding.file), Number.isInteger(finding.line) ? finding.line : null, JSON.stringify(finding));
      }
      db.prepare('UPDATE scans SET body_json=?,body_sha256=?,verdict=?,finding_count=(SELECT COUNT(*) FROM findings WHERE scan_id=?) WHERE id=?').run(serialized, bodyHash, outcome.expediente.auditVerdict && outcome.expediente.auditVerdict.verdict || scan.verdict, scan.id, scan.id);
      db.prepare('INSERT INTO stages(scan_id,stage,state,detail,at) VALUES(?,?,?,?,?)').run(scan.id, 'SPECIALIST_EXTENSION', 'COMPLETE', JSON.stringify(body.tools || []), new Date().toISOString());
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    return json(res, 200, { result: updated });
  });
  return null;
}

function startWebDashboard(options = {}) {
  const port = options.port == null ? 4317 : Number(options.port);
  let db;
  try { db = database(options.databasePath || DB_PATH); }
  catch (error) {
    throw new Error(`No se pudo abrir SQLite. El dashboard requiere Node.js 22.5 o superior: ${error.message}`);
  }
  const server = http.createServer((req, res) => {
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('referrer-policy', 'no-referrer');
    Promise.resolve().then(() => {
      const result = handle(req, res, db);
      if (result && typeof result.then === 'function') result.catch((error) => { if (!res.headersSent) json(res, error.status || 400, { error: safeError(error) }); });
      else if (result === null && req.method === 'GET' && !req.url.startsWith('/api/')) {
        const requested = req.url === '/' ? '/index.html' : decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
        const file = path.resolve(PUBLIC, `.${requested}`);
        if (!file.startsWith(`${PUBLIC}${path.sep}`) && file !== path.join(PUBLIC, 'index.html')) return json(res, 403, { error: 'Ruta inválida.' });
        if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return json(res, 404, { error: 'No encontrado.' });
        const mime = file.endsWith('.css') ? 'text/css; charset=utf-8' : file.endsWith('.js') ? 'text/javascript; charset=utf-8' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html; charset=utf-8';
        res.writeHead(200, { 'content-type': mime, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(fs.readFileSync(file));
      } else if (result === null && !res.writableEnded) json(res, 404, { error: 'Endpoint no encontrado.' });
    }).catch((error) => { if (!res.headersSent) json(res, error.status || 400, { error: safeError(error) }); });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', reject);
      process.stdout.write(`Sentinel Audit local dashboard: http://127.0.0.1:${server.address().port}\nDatabase: ${options.databasePath || DB_PATH}\nPress Ctrl+C to stop.\n`);
      resolve(server);
    });
    server.once('close', () => db.close());
  });
}

module.exports = { startWebDashboard, database, cloudStatus, state, normalizedSeverity, evidencePath };
