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
const cloudSettings = require('../lib/cloud-settings');

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
    CREATE TABLE IF NOT EXISTS scan_revisions (
      revision_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, repo TEXT NOT NULL, pr_number INTEGER NOT NULL,
      head_sha TEXT NOT NULL, mode TEXT NOT NULL, verdict TEXT, risk_score INTEGER,
      finding_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, started_at TEXT NOT NULL,
      finished_at TEXT, body_sha256 TEXT, diff_sha256 TEXT, snapshot_json TEXT NOT NULL,
      captured_at TEXT NOT NULL, reason TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS stages_scan_idx ON stages(scan_id);
    CREATE INDEX IF NOT EXISTS scan_revisions_key_idx ON scan_revisions(repo,pr_number,mode,started_at DESC);
  `);
  const duplicateKeys = db.prepare('SELECT repo,pr_number,mode FROM scans GROUP BY repo,pr_number,mode HAVING COUNT(*)>1').all();
  if (duplicateKeys.length) {
    db.exec('BEGIN');
    try {
      for (const key of duplicateKeys) {
        const rows = db.prepare('SELECT * FROM scans WHERE repo=? AND pr_number=? AND mode=? ORDER BY started_at DESC,id DESC').all(key.repo,key.pr_number,key.mode);
        for (const duplicate of rows.slice(1)) {
          archiveScanSnapshot(db, duplicate, 'legacy duplicate consolidated during database migration');
          db.prepare('DELETE FROM scans WHERE id=?').run(duplicate.id);
        }
      }
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS scans_repo_pr_mode_unique ON scans(repo,pr_number,mode)');
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

function archiveScanSnapshot(db, row, reason) {
  const findings = db.prepare('SELECT source,severity,category,title,file,line,evidence FROM findings WHERE scan_id=? ORDER BY id').all(row.id);
  const stages = db.prepare('SELECT stage,state,detail,at FROM stages WHERE scan_id=? ORDER BY id').all(row.id);
  const snapshot = { schema: 'sentinel-audit-forensic-revision/1.0', scan: row, findings, stages };
  const revisionId = `revision-${crypto.randomUUID()}`;
  db.prepare(`INSERT INTO scan_revisions(revision_id,scan_id,repo,pr_number,head_sha,mode,verdict,risk_score,finding_count,status,started_at,finished_at,body_sha256,diff_sha256,snapshot_json,captured_at,reason)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(revisionId,row.id,row.repo,row.pr_number,row.head_sha,row.mode,row.verdict,row.risk_score,row.finding_count,row.status,row.started_at,row.finished_at,row.body_sha256,row.diff_sha256,JSON.stringify(snapshot),new Date().toISOString(),reason);
  return revisionId;
}

function scanDocument(db, id) {
  const current = db.prepare('SELECT body_json FROM scans WHERE id=?').get(id);
  if (current && current.body_json) return JSON.parse(current.body_json);
  const archived = db.prepare('SELECT snapshot_json FROM scan_revisions WHERE revision_id=?').get(id);
  if (!archived) return null;
  const snapshot = JSON.parse(archived.snapshot_json);
  return snapshot.scan && snapshot.scan.body_json ? JSON.parse(snapshot.scan.body_json) : null;
}

function readPrimaryEngineArtifact(document) {
  const engine = document && document.audit && document.audit.tools && document.audit.tools.sentinel;
  const rootValue = document && (document.executionDir || document.audit && document.audit.executionDir);
  if (!engine || !engine.rawArtifact || !rootValue) throw Object.assign(new Error('Este expediente no conserva un cuerpo crudo del motor principal.'), { status: 404 });
  let root; let artifact;
  try {
    root = fs.realpathSync(path.resolve(rootValue));
    artifact = fs.realpathSync(path.isAbsolute(engine.rawArtifact) ? engine.rawArtifact : path.resolve(root, engine.rawArtifact));
  } catch (_) { throw Object.assign(new Error('El artefacto crudo del motor ya no está disponible en el almacenamiento local.'), { status: 404 }); }
  const relative = path.relative(root, artifact);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw Object.assign(new Error('La ruta del artefacto sale del directorio de ejecución.'), { status: 403 });
  const stat = fs.statSync(artifact);
  if (!stat.isFile()) throw Object.assign(new Error('El artefacto crudo no es un archivo JSON.'), { status: 404 });
  if (stat.size > 25 * 1024 * 1024) throw Object.assign(new Error('El cuerpo crudo supera 25 MB; consúltalo directamente en el directorio local del expediente.'), { status: 413 });
  const bytes = fs.readFileSync(artifact);
  let body;
  try { body = JSON.parse(bytes.toString('utf8')); }
  catch (_) { throw Object.assign(new Error('El cuerpo crudo guardado no contiene JSON válido.'), { status: 422 }); }
  const engineLabel = document.mode === 'pulse' ? 'Sentinel Cloud · Pulse' : document.mode === 'local' ? 'Sentinel motor local completo' : 'Sentinel Audit Lite · señales de entrada';
  return { engine: engineLabel, status: engine.status || 'UNKNOWN', mode: document.mode, artifact: relative.split(path.sep).join('/'), sha256: crypto.createHash('sha256').update(bytes).digest('hex'), body };
}

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000, windowsHide: true });
}

function countOpenPullRequests(repositories) {
  const counts = new Map();
  const valid = repositories.filter((repo) => typeof repo.nameWithOwner === 'string' && /^[\w.-]+\/[\w.-]+$/.test(repo.nameWithOwner));
  for (let offset = 0; offset < valid.length; offset += 25) {
    const batch = valid.slice(offset, offset + 25);
    const fields = batch.map((repo, index) => {
      const [owner, name] = repo.nameWithOwner.split('/');
      return `r${index}: repository(owner: "${owner}", name: "${name}") { pullRequests(states: OPEN) { totalCount } }`;
    });
    try {
      const result = JSON.parse(gh(['api', 'graphql', '-f', `query=query { ${fields.join(' ')} }`]));
      batch.forEach((repo, index) => {
        const value = result.data && result.data[`r${index}`] && result.data[`r${index}`].pullRequests;
        counts.set(repo.nameWithOwner, value && Number.isInteger(value.totalCount) ? value.totalCount : null);
      });
    } catch (_) {
      batch.forEach((repo) => counts.set(repo.nameWithOwner, null));
    }
  }
  return repositories.map((repo) => ({ ...repo, openPrCount: counts.has(repo.nameWithOwner) ? counts.get(repo.nameWithOwner) : null }));
}

function cloudStatus() {
  const { tools, policies } = loadConfig();
  const entries = keys.listKeys();
  const client = resolveClient({ tools }, {});
  const localSettings = cloudSettings.read();
  const configuredUrl = localSettings.url || process.env.SENTINEL_CLOUD_URL || cloudSettings.DEFAULT_ENDPOINT;
  const endpointSource = localSettings.url ? 'local-settings' : process.env.SENTINEL_CLOUD_URL ? 'environment' : 'default';
  let url = null; let endpointHost = null; let urlError = null;
  if (configuredUrl) {
    try { url = cloudSettings.validateEndpoint(configuredUrl); endpointHost = new URL(url).host; }
    catch (error) { urlError = error.message; }
  }
  const policyEnabled = !!(policies.hosted && policies.hosted.enabled);
  const reasons = [];
  if (!policyEnabled) reasons.push(entries.length ? 'La clave API local sí existe, pero Pulse está desactivado por la política de Sentinel Audit. Actívalo en la configuración de Pulse.' : 'Pulse está desactivado por la política de Sentinel Audit.');
  if (!client) reasons.push('No se encuentra @sentinel/cloud-client.');
  if (!url && urlError) reasons.push(`La URL de Sentinel Cloud no es válida: ${urlError}`);
  else if (!url) reasons.push('Falta la URL de Sentinel Cloud. Configúrala en Pulse o en SENTINEL_CLOUD_URL.');
  if (!entries.length) reasons.push('No hay claves de Sentinel Cloud guardadas en esta máquina.');
  return { enabled: policyEnabled && !!client && !!url && entries.length > 0, reasons, keys: entries, urlConfigured: !!url, endpointUrl: url, endpointHost, endpointSource, clientAvailable: !!client, policyEnabled };
}

function state() {
  const { tools, policies } = loadConfig();
  const github = checkGitHubSession();
  const health = checkToolHealth(tools);
  const installable = new Set(toolInstaller.supportedTools());
  const specialists = Object.entries(health).filter(([name]) => name !== 'sentinel').map(([name, item]) => ({ id: name, name: name === 'zizmor' ? 'Zizmor · CI/CD' : name, category: 'specialist', installable: installable.has(name), available: !!item.available, installed: !!item.path, state: item.state, blockedByHost: !!item.blockedByHost, path: item.path || null, reason: item.blockedByHost ? `Encontrado en ${item.path}; el runtime guard bloquea su ejecución en este proceso.` : name === 'zizmor' && !item.available ? 'No instalado. Descárgalo desde Herramientas o configura SPECIALIST_ZIZMOR_PATH.' : item.reason || null }));
  const cloud = cloudStatus();
  const localEngine = health.sentinel || { available: false, state: 'UNAVAILABLE', reason: 'No se detectó el motor local Sentinel Cloud.' };
  const toolRows = [
    { id: 'sentinel-local', name: 'Sentinel Audit Lite (PR diff)', category: 'engine', available: true, installed: true, state: 'AVAILABLE', path: null, reason: 'Analizador Lite del diff fijado por SHA. No invoca el motor local completo de Sentinel Cloud.' },
    { id: 'sentinel-engine-local', name: 'Sentinel motor local completo', category: 'engine', available: !!localEngine.available, installed: !!localEngine.available, state: localEngine.available ? 'AVAILABLE' : 'UNAVAILABLE', path: localEngine.path || null, reason: localEngine.reason || null },
    { id: 'sentinel-cloud', name: 'Sentinel Cloud (Pulse)', category: 'cloud', available: !!cloud.enabled, installed: !!cloud.enabled, state: cloud.enabled ? 'AVAILABLE' : 'UNAVAILABLE', path: null, reason: cloud.enabled ? 'Pulse habilitado: consume pulsos de Sentinel Cloud con la clave guardada.' : cloud.reasons.join(' ') || 'Pulse no configurado.' },
    ...specialists
  ];
  const publicCloud = { enabled: cloud.enabled, reasons: cloud.reasons, keys: cloud.keys, urlConfigured: cloud.urlConfigured, endpointHost: cloud.endpointHost, endpointSource: cloud.endpointSource, clientAvailable: cloud.clientAvailable, policyEnabled: cloud.policyEnabled };
  return { github, currentRepo: detectCurrentRepo(), tools: toolRows, cloud: publicCloud, localEngine: { available: !!localEngine.available, reason: localEngine.reason || null }, policies: { hostedEnabled: !!(policies.hosted && policies.hosted.enabled) }, database: DB_PATH };
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
function findingLabel(finding) {
  const rule = finding && finding.rule;
  const ruleLabel = typeof rule === 'string' ? rule : rule && typeof rule === 'object' ? (rule.id || rule.message || rule.title || null) : null;
  const typeLabel = typeof finding.type === 'string' ? finding.type : null;
  const candidates = [finding.title, finding.message, finding.name, ruleLabel, finding.checkId, finding.ruleId, finding.detail, typeLabel, finding.kind];
  const label = candidates.find((value) => typeof value === 'string' && value.trim());
  return label ? label.slice(0, 300) : 'Señal sin título';
}
function findingCategory(finding) {
  if (finding.category != null && String(finding.category).trim()) return String(finding.category).slice(0, 80);
  if (finding.kind != null && String(finding.kind).trim()) return String(finding.kind).slice(0, 80);
  return null;
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
  const requestedMode = String(payload.mode || 'lite').toLowerCase();
  if (!['lite', 'local', 'pulse'].includes(requestedMode)) throw new Error('Unknown analysis mode');
  const mode = requestedMode;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || !Number.isSafeInteger(number) || number < 1) throw new Error('Repositorio o número de PR inválido.');
  const cloud = cloudStatus();
  if (mode === 'pulse' && !cloud.enabled) throw new Error(`Pulse no está disponible: ${cloud.reasons.join(' ')}`);
  if (mode === 'local' && !state().localEngine.available) throw new Error('Full local Sentinel engine is unavailable');
  const selectedKey = mode === 'pulse' ? keys.getKey(payload.keyId || cloud.keys[0] && cloud.keys[0].id || 1) : null;
  if (mode === 'pulse' && !selectedKey) throw Object.assign(new Error('La clave seleccionada no está en el almacén local de Sentinel Audit. Actualiza Claves API y selecciónala de nuevo.'), { status: 400 });
  const existing = db.prepare('SELECT * FROM scans WHERE repo=? AND pr_number=? AND mode=?').get(repo, number, mode);
  if (existing && existing.status === 'RUNNING') throw Object.assign(new Error(`Ya hay un escaneo ${mode} en curso para ${repo}#${number}.`), { status: 409 });
  const id = existing ? existing.id : `web-${crypto.randomUUID()}`;
  const startedAt = new Date().toISOString();
  let previousRevisionId = null;
  db.exec('BEGIN');
  try {
    if (existing) {
      previousRevisionId = archiveScanSnapshot(db, existing, 'superseded by an explicit re-scan');
      db.prepare('DELETE FROM findings WHERE scan_id=?').run(id);
      db.prepare('DELETE FROM stages WHERE scan_id=?').run(id);
      db.prepare(`UPDATE scans SET head_sha='PENDING',verdict=NULL,risk_score=NULL,finding_count=0,status='RUNNING',started_at=?,finished_at=NULL,body_sha256=NULL,diff_sha256=NULL,body_json=NULL,error=NULL WHERE id=?`).run(startedAt,id);
    } else {
      db.prepare(`INSERT INTO scans(id,repo,pr_number,head_sha,mode,status,started_at) VALUES(?,?,?,?,?,'RUNNING',?)`).run(id, repo, number, 'PENDING', mode, startedAt);
    }
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); throw error; }
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
      checkout = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-web-'));
      const source = path.join(checkout, 'source');
      execFileSync('git', ['clone', '--quiet', '--no-checkout', `https://github.com/${repo}.git`, source], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000, windowsHide: true });
      execFileSync('git', ['-C', source, 'fetch', '--quiet', '--depth=1', 'origin', `refs/pull/${number}/head`], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000, windowsHide: true });
      execFileSync('git', ['-C', source, 'checkout', '--quiet', '--detach', meta.headRefOid], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000, windowsHide: true });
      const seedFindings = lite.findings.map((f) => ({ type: f.ruleId || f.rule || f.title, title: f.title, description: f.description, message: f.title, snippet: f.snippet || null, file: f.file, line: Number.isInteger(f.line) && f.line > 0 ? f.line : null, severity: ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2 })[String(f.severity).toUpperCase()] || 1, evidence: [f.ruleId || f.rule || f.title].filter(Boolean) }));
      const pipelineOptions = { name: `${repo.replace('/', '-')}-pr-${number}`, commit: meta.headRefOid, routing: 'file', onProgress: (event) => recordStage(db, id, event.stage, event.state, event.detail) };
      if (mode === 'pulse') Object.assign(pipelineOptions, { provider: 'cloud', apiToken: selectedKey.token, apiUrl: cloud.endpointUrl });
      else if (mode === 'lite') Object.assign(pipelineOptions, { seedFindings, seedEngine: 'Sentinel Audit Lite PR diff' });
      // local mode leaves seedFindings unset so runAuditV1 invokes the configured
      // local Sentinel engine instead of reusing the quick diff scanner.
      const result = await runAuditV1(source, pipelineOptions);
      recordStage(db, id, 'PIPELINE_COMPLETE', 'COMPLETE', { verdict: result.expediente.auditVerdict && result.expediente.auditVerdict.verdict, executionDir: result.executionDir });
      const auditTools = result.expediente.tools || {};
      const signalRouting = result.expediente.signalRouting || {};
      const independentChecks = Array.isArray(signalRouting.independentChecks) ? signalRouting.independentChecks : [];
      const independentNames = new Set(independentChecks.map((item) => item.tool));
      const sourceSignals = mode === 'lite' ? (lite.findings || []).length : (auditTools.sentinel && auditTools.sentinel.findings || []).length;
      const primary = mode === 'lite'
        ? { id: 'sentinel-audit-lite', label: 'Sentinel Audit Lite · diff del PR', scope: 'Diff exacto fijado por SHA' }
        : mode === 'local'
          ? { id: 'sentinel-local', label: 'Motor Sentinel local completo', scope: 'Checkout completo fijado por SHA' }
          : { id: 'sentinel-cloud-pulse', label: 'Sentinel Cloud · Pulse', scope: 'Checkout fijado enviado al motor Cloud' };
      const analysisProvenance = {
        primary, primarySignalCount: sourceSignals,
        routedByPrimarySignals: (signalRouting.tools || []).filter((tool) => !independentNames.has(tool)),
        independentChecks,
        executedSpecialists: Object.keys(auditTools).filter((tool) => tool !== 'sentinel'),
        routingReason: signalRouting.reason || null,
        liteReference: mode === 'lite' ? null : { label: 'Sentinel Audit Lite · diff del PR', sha256: diffHash, role: 'Referencia paralela; no origina el enrutamiento del motor seleccionado.' },
        flow: mode === 'lite'
          ? 'Lite analiza el diff; sus señales normalizadas alimentan el enrutamiento hacia especialistas.'
          : 'El resultado del motor elegido alimenta el enrutamiento hacia especialistas; Lite queda como referencia separada del diff.',
      };
      const body = { schema: 'sentinel-audit-web-scan/1.0', id, repository: repo, pullRequest: { number, title: meta.title, url: meta.url, author: meta.author && meta.author.login || null, base: meta.baseRefName, head: meta.headRefName, commit: meta.headRefOid }, mode, createdAt: startedAt, diff: { sha256: diffHash, bytes: Buffer.byteLength(diff), files: lite.filesAnalyzed }, lite, analysisProvenance, audit: result.expediente, executionDir: result.executionDir, stageTimeline: SCANS.get(id).events };
      const canonical = JSON.stringify(body);
      const bodyHash = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
      body.integrity = { algorithm: 'SHA-256', bodyHash, diffHash };
      const serialized = JSON.stringify(body);
      const findings = [...(lite.findings || []).map((f) => ({ source: 'sentinel-lite', ...f })), ...Object.entries(result.expediente.tools || {}).flatMap(([sourceName, item]) => (item.findings || []).map((f) => ({ source: sourceName, ...f })))];
      db.prepare(`UPDATE scans SET head_sha=?,verdict=?,risk_score=?,finding_count=?,status='COMPLETE',finished_at=?,body_sha256=?,diff_sha256=?,body_json=? WHERE id=?`).run(meta.headRefOid, result.expediente.auditVerdict && result.expediente.auditVerdict.verdict || lite.verdict, lite.riskScore, findings.length, new Date().toISOString(), bodyHash, diffHash, serialized, id);
      const addFinding = db.prepare('INSERT INTO findings(scan_id,source,severity,category,title,file,line,evidence) VALUES(?,?,?,?,?,?,?,?)');
      for (const f of findings) addFinding.run(id, f.source || 'unknown', normalizedSeverity(f.severity == null && f.rawEngineSignal ? f.rawEngineSignal.severity : f.severity), findingCategory(f) || null, findingLabel(f), evidencePath(f.file), Number.isInteger(f.line) ? f.line : null, JSON.stringify(f));
      SCANS.get(id).state = 'COMPLETE'; SCANS.get(id).result = body;
    } catch (error) {
      recordStage(db, id, 'FAILED', 'FAILED', safeError(error));
      db.prepare("UPDATE scans SET status='FAILED',finished_at=?,error=? WHERE id=?").run(new Date().toISOString(), safeError(error), id);
      SCANS.get(id).state = 'FAILED'; SCANS.get(id).error = safeError(error);
    } finally { if (checkout) try { fs.rmSync(checkout, { recursive: true, force: true }); } catch (_) {} }
  });
  return { id, state: 'RUNNING', updatedExisting: !!existing, previousRevisionId };
}

function handle(req, res, db) {
  assertLocal(req);
  const url = new URL(req.url, 'http://127.0.0.1');
  const method = req.method;
  const route = url.pathname;
  if (method === 'GET' && route === '/api/state') return json(res, 200, state());
  if (method === 'GET' && route === '/api/cloud/settings') {
    const cloud = cloudStatus();

    return json(res, 200, { enabled: cloud.policyEnabled, url: cloud.endpointUrl || '', endpointSource: cloud.endpointSource, defaultUrl: cloudSettings.DEFAULT_ENDPOINT, endpointHost: cloud.endpointHost, keys: cloud.keys, clientAvailable: cloud.clientAvailable, reasons: cloud.reasons });
  }
  if (method === 'POST' && route === '/api/cloud/settings') return readBody(req).then((body) => {
    const enabled = body.enabled === true;
    const current = cloudStatus();
    const requestedUrl = String(body.url || '').trim();
    const candidateUrl = requestedUrl || current.endpointUrl || cloudSettings.DEFAULT_ENDPOINT;
    cloudSettings.validateEndpoint(candidateUrl);
    if (enabled && !keys.listKeys().length) throw Object.assign(new Error('Guarda al menos una clave API antes de activar Pulse.'), { status: 400 });
    const saved = cloudSettings.save({ enabled, url: requestedUrl || null });
    const cloud = cloudStatus();
    return json(res, 200, { enabled: cloud.enabled, policyEnabled: cloud.policyEnabled, urlConfigured: cloud.urlConfigured, endpointSource: cloud.endpointSource, endpointHost: cloud.endpointHost, endpointUrl: saved.url || cloudSettings.DEFAULT_ENDPOINT, keys: cloud.keys, clientAvailable: cloud.clientAvailable, reasons: cloud.reasons });
  });
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
    const repositories = JSON.parse(gh(['repo', 'list', ghState.account, '--json', 'nameWithOwner,description,isPrivate', '--limit', '100']));
    return json(res, 200, { repositories: countOpenPullRequests(repositories) });
  }
  const prMatch = route.match(/^\/api\/repos\/([\w.-]+)\/([\w.-]+)\/pulls$/);
  if (method === 'GET' && prMatch) {
    const repo = `${prMatch[1]}/${prMatch[2]}`;
    const pullRequests = JSON.parse(gh(['pr', 'list', '--repo', repo, '--json', 'number,title,author,headRefName,headRefOid,updatedAt,url,labels', '--limit', '50']));
    const scans = db.prepare('SELECT id,pr_number,status,mode,started_at FROM scans WHERE repo=? ORDER BY started_at DESC,id DESC').all(repo);
    const latest = new Map();
    for (const scan of scans) if (!latest.has(scan.pr_number)) latest.set(scan.pr_number, scan);
    const severityRows = db.prepare('SELECT severity,COUNT(*) AS count FROM findings WHERE scan_id=? GROUP BY severity');
    const withAudit = pullRequests.map((pr) => {
      const scan = latest.get(pr.number);
      if (!scan) return { ...pr, latestAudit: null };
      const severities = scan.status === 'COMPLETE' ? severityRows.all(scan.id).map((row) => ({ severity: row.severity || 'UNSPECIFIED', count: row.count })) : [];
      return { ...pr, latestAudit: { status: scan.status, mode: scan.mode, startedAt: scan.started_at, severities } };
    });
    return json(res, 200, { pullRequests: withAudit });
  }
  if (method === 'GET' && route === '/api/scans') return json(res, 200, { scans: db.prepare('SELECT id,repo,pr_number,head_sha,mode,verdict,risk_score,finding_count,status,started_at,finished_at,body_sha256,diff_sha256,error FROM scans ORDER BY started_at DESC LIMIT 200').all() });
  if (method === 'GET' && route === '/api/forensics') {
    const filters = {
      q: String(url.searchParams.get('q') || '').trim().slice(0, 180),
      sha: String(url.searchParams.get('sha') || '').trim().toLowerCase(),
      repo: String(url.searchParams.get('repo') || '').trim().slice(0, 160),
      pr: String(url.searchParams.get('pr') || '').trim().slice(0, 12),
      mode: String(url.searchParams.get('mode') || '').trim().slice(0, 20),
      engine: String(url.searchParams.get('engine') || '').trim().slice(0, 40),
      severity: String(url.searchParams.get('severity') || '').trim().toUpperCase().slice(0, 20),
    };
    if (filters.sha && !/^[a-f0-9]{4,64}$/.test(filters.sha)) return json(res, 400, { error: 'El SHA debe tener entre 4 y 64 caracteres hexadecimales.' });
    const buildWhere = (contentColumn, historical) => {
      const clauses = ['1=1']; const params = [];
      if (filters.q) {
        const like = `%${filters.q}%`;
        clauses.push(`(s.repo LIKE ? OR CAST(s.pr_number AS TEXT) LIKE ? OR s.head_sha LIKE ? OR s.mode LIKE ? OR COALESCE(s.verdict,'') LIKE ? OR s.status LIKE ? OR COALESCE(s.body_sha256,'') LIKE ? OR COALESCE(s.diff_sha256,'') LIKE ? OR ${contentColumn} LIKE ?)`);
        params.push(like,like,like,like,like,like,like,like,like);
      }
      if (filters.sha) { const like = `%${filters.sha}%`; clauses.push('(s.head_sha LIKE ? OR COALESCE(s.body_sha256,\'\') LIKE ? OR COALESCE(s.diff_sha256,\'\') LIKE ?)'); params.push(like,like,like); }
      if (filters.repo) { clauses.push('s.repo LIKE ?'); params.push(`%${filters.repo}%`); }
      if (filters.pr) { clauses.push('CAST(s.pr_number AS TEXT) LIKE ?'); params.push(`%${filters.pr}%`); }
      if (filters.mode) { clauses.push('s.mode=?'); params.push(filters.mode); }
      if (filters.engine) {
        const like = `%${filters.engine}%`;
        clauses.push(historical ? `${contentColumn} LIKE ?` : `(EXISTS (SELECT 1 FROM findings f WHERE f.scan_id=s.id AND f.source LIKE ?) OR ${contentColumn} LIKE ?)`);
        params.push(like); if (!historical) params.push(like);
      }
      if (filters.severity) {
        const quote = String.fromCharCode(34);
        const escapedQuote = `${String.fromCharCode(92)}${quote}`;
        const like = historical
          ? `%${escapedQuote}severity${escapedQuote}:${escapedQuote}${filters.severity}${escapedQuote}%`
          : `%${quote}severity${quote}:${quote}${filters.severity}${quote}%`;
        clauses.push(historical ? `${contentColumn} LIKE ?` : `(EXISTS (SELECT 1 FROM findings f WHERE f.scan_id=s.id AND UPPER(f.severity)=?) OR ${contentColumn} LIKE ?)`);
        if (historical) params.push(like); else params.push(filters.severity,like);
      }
      return { sql: clauses.join(' AND '), params };
    };
    const currentWhere = buildWhere('COALESCE(s.body_json,\'\')', false);
    const historyWhere = buildWhere('s.snapshot_json', true);
    const current = db.prepare(`SELECT id AS result_id,id AS scan_id,repo,pr_number,head_sha,mode,verdict,risk_score,finding_count,status,started_at,finished_at,body_sha256,diff_sha256,'CURRENT' AS record_type FROM scans s WHERE ${currentWhere.sql} ORDER BY started_at DESC LIMIT 200`).all(...currentWhere.params);
    const history = db.prepare(`SELECT revision_id AS result_id,scan_id,repo,pr_number,head_sha,mode,verdict,risk_score,finding_count,status,started_at,finished_at,body_sha256,diff_sha256,'HISTORICAL' AS record_type FROM scan_revisions s WHERE ${historyWhere.sql} ORDER BY started_at DESC LIMIT 200`).all(...historyWhere.params);
    const results = [...current,...history].sort((a,b)=>String(b.started_at).localeCompare(String(a.started_at))).slice(0,200);
    return json(res, 200, { filters, count: results.length, results });
  }
  if (method === 'GET' && route === '/api/analytics') {
    return json(res, 200, { severities: db.prepare('SELECT severity,COUNT(*) count FROM findings GROUP BY severity ORDER BY count DESC').all(), sources: db.prepare('SELECT source,COUNT(*) count FROM findings GROUP BY source ORDER BY count DESC').all(), files: db.prepare('SELECT file,COUNT(*) count FROM findings WHERE file IS NOT NULL GROUP BY file ORDER BY count DESC LIMIT 12').all(), timeline: db.prepare("SELECT substr(started_at,1,10) day,COUNT(*) count FROM scans GROUP BY day ORDER BY day").all(), categories: db.prepare('SELECT category,COUNT(*) count FROM findings GROUP BY category ORDER BY count DESC').all() });
  }
  if (method === 'GET' && route === '/api/findings') {
    const category = url.searchParams.get('category');
    const file = url.searchParams.get('file');
    if (!category && !file) return json(res, 400, { error: 'Indica category o file para consultar el historial.' });
    const clauses = []; const params = [];
    if (category) { clauses.push(category === '__none__' ? 'f.category IS NULL' : 'f.category=?'); if (category !== '__none__') params.push(category); }
    if (file) { clauses.push('f.file=?'); params.push(file); }
    const rows = db.prepare(`SELECT f.id,f.scan_id,f.source,f.severity,f.category,f.title,f.file,f.line,f.evidence,s.repo,s.pr_number,s.mode,s.verdict,s.started_at FROM findings f JOIN scans s ON s.id=f.scan_id WHERE ${clauses.join(' AND ')} ORDER BY s.started_at DESC, f.id DESC LIMIT 300`).all(...params);
    return json(res, 200, { category: category || null, file: file || null, rows });
  }
  if (method === 'GET' && route === '/api/database') {
    const allowed = { scans: 'SELECT * FROM scans', findings: 'SELECT * FROM findings', stages: 'SELECT * FROM stages', scan_revisions: 'SELECT revision_id,scan_id,repo,pr_number,head_sha,mode,verdict,risk_score,finding_count,status,started_at,finished_at,body_sha256,diff_sha256,captured_at,reason FROM scan_revisions' };
    const table = url.searchParams.get('table') || 'scans';
    if (!allowed[table]) return json(res, 400, { error: 'Tabla no permitida.' });
    const rows = db.prepare(`${allowed[table]} ORDER BY 1 DESC LIMIT 250`).all();
    return json(res, 200, { table, rows });
  }
  const scanMatch = route.match(/^\/api\/scans\/([\w-]+)$/);
  const engineBodyMatch = route.match(/^\/api\/scans\/([\w-]+)\/engine-body$/);
  if (method === 'GET' && engineBodyMatch) {
    const document = scanDocument(db, engineBodyMatch[1]);
    if (!document) return json(res, 404, { error: 'El resultado del escaneo no está disponible.' });
    return json(res, 200, readPrimaryEngineArtifact(document));
  }
  if (method === 'GET' && scanMatch) {
    const id = scanMatch[1]; const row = db.prepare('SELECT * FROM scans WHERE id=?').get(id);
    if (!row) {
      const revision = db.prepare('SELECT snapshot_json FROM scan_revisions WHERE revision_id=?').get(id);
      if (!revision) return json(res, 404, { error: 'Scan no encontrado.' });
      let snapshot; try { snapshot = JSON.parse(revision.snapshot_json); } catch (_) { return json(res, 500, { error: 'La revisión forense guardada está dañada.' }); }
      const scan = snapshot.scan || {};
      return json(res, 200, { id, status: scan.status, historical: true, events: snapshot.stages || [], result: scan.body_json ? JSON.parse(scan.body_json) : null, reason: 'Revisión archivada antes de actualizar el registro actual.' });
    }
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
        addFinding.run(scan.id, sourceName, normalizedSeverity(finding.severity == null && finding.rawEngineSignal ? finding.rawEngineSignal.severity : finding.severity), findingCategory(finding) || null, findingLabel(finding), evidencePath(finding.file), Number.isInteger(finding.line) ? finding.line : null, JSON.stringify(finding));
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
