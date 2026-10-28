'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { pipeline } = require('node:stream/promises');
const { Transform } = require('node:stream');
const { loadConfig } = require('../lib/core');

const STORE = path.join(os.homedir(), '.sentinel-audit', 'tools');
const PATH_CONFIG = path.join(os.homedir(), '.sentinel-audit', 'tool-paths.json');
const ACTIVE = new Set();
const JOBS = new Map();
const MAX_RELEASE_BYTES = 2 * 1024 * 1024 * 1024;
const SPECS = Object.freeze({
  codeql: { kind: 'github-zip', repo: 'github/codeql-cli-binaries', asset: /^codeql-win64\.zip$/, executable: /(?:^|\/)codeql\/codeql\.exe$/i, licenseRequired: true },
  trivy: { kind: 'github-zip', repo: 'aquasecurity/trivy', asset: /^trivy_[\d.]+_windows-64bit\.zip$/i, executable: /(?:^|\/)trivy\.exe$/i },
  osv: { kind: 'github-binary', repo: 'google/osv-scanner', asset: /^osv-scanner_windows_amd64\.exe$/i, executable: /osv-scanner\.exe$/i },
  shellcheck: { kind: 'github-zip', repo: 'koalaman/shellcheck', asset: /^shellcheck-v[\d.]+\.zip$/i, executable: /(?:^|\/)shellcheck\.exe$/i },
  semgrep: { kind: 'pypi', package: 'semgrep', executableName: 'semgrep.exe' },
  bandit: { kind: 'pypi', package: 'bandit', executableName: 'bandit.exe' },
});

function publicJob(job) { const { error, ...safe } = job; return { ...safe, error: error || null }; }
function listJobs() { return [...JOBS.values()].map(publicJob).sort((a, b) => b.startedAt.localeCompare(a.startedAt)); }
function getJob(id) { const job = JOBS.get(id); return job ? publicJob(job) : null; }
function progress(job, state, percent, message) { job.state = state; job.percent = Math.max(0, Math.min(100, Math.round(percent))); job.message = String(message || '').slice(0, 300); job.updatedAt = new Date().toISOString(); }
function writeToolPath(tool, binary) {
  fs.mkdirSync(path.dirname(PATH_CONFIG), { recursive: true, mode: 0o700 });
  let config = {};
  try { config = JSON.parse(fs.readFileSync(PATH_CONFIG, 'utf8')); } catch (_) {}
  config[tool] = path.resolve(binary);
  const temp = `${PATH_CONFIG}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(temp, PATH_CONFIG);
}
function setToolOverride(tools, tool, binary) {
  tools[tool] = { ...(tools[tool] || {}), path: binary };
}
function validateTool(tool) { if (!Object.hasOwn(SPECS, tool)) throw Object.assign(new Error('Herramienta de instalación no permitida.'), { status: 404 }); }
function startInstall(tool, options = {}) {
  validateTool(tool);
  if (process.platform !== 'win32') throw Object.assign(new Error('El instalador integrado está disponible solo para Windows. Usa el enlace oficial de instalación en otros sistemas.'), { status: 400 });
  if (ACTIVE.size) throw Object.assign(new Error('Ya hay una instalación en curso.'), { status: 409 });
  if (SPECS[tool].licenseRequired && options.acceptLicenseTerms !== true) throw Object.assign(new Error('Lee y acepta las condiciones de uso de CodeQL antes de descargarlo.'), { status: 400 });
  for (const [jobId, job] of JOBS) {
    if (JOBS.size < 100) break;
    if (!ACTIVE.has(jobId)) JOBS.delete(jobId);
  }
  const id = crypto.randomUUID();
  const job = { id, tool, state: 'QUEUED', percent: 0, message: 'En cola', startedAt: new Date().toISOString(), updatedAt: new Date().toISOString(), version: null, error: null };
  JOBS.set(id, job); ACTIVE.add(id);
  install(job).catch((error) => { job.error = String(error && error.message || error).replace(/(?:Bearer\s+\S+|sntl_[A-Za-z0-9_-]+)/gi, '[redacted]').slice(0, 1000); progress(job, 'FAILED', job.percent, 'No se completó la instalación.'); }).finally(() => ACTIVE.delete(id));
  return publicJob(job);
}

async function githubRelease(spec) {
  const url = `https://api.github.com/repos/${spec.repo}/releases/latest`;
  const response = await fetch(url, { headers: { accept: 'application/vnd.github+json', 'user-agent': 'sentinel-audit-local-tool-installer' }, signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`GitHub Release API respondió HTTP ${response.status}.`);
  const release = await response.json();
  const asset = (release.assets || []).find((item) => spec.asset.test(item.name));
  if (!asset || !/^https:\/\/github\.com\//i.test(asset.browser_download_url || '') || !Number.isFinite(asset.size) || asset.size <= 0 || asset.size > MAX_RELEASE_BYTES) throw new Error('No se encontró un artefacto oficial de Windows dentro del límite de tamaño.');
  if (!/^sha256:[a-f\d]{64}$/i.test(asset.digest || '')) throw new Error('El release no publica un digest SHA-256 verificable en la API de GitHub; se canceló la instalación.');
  return { release, asset, digest: asset.digest.slice(7).toLowerCase() };
}

async function downloadAsset(job, asset, expectedDigest, destination) {
  progress(job, 'DOWNLOADING', 1, `Descargando ${asset.name} desde el release oficial`);
  const response = await fetch(asset.browser_download_url, { headers: { 'user-agent': 'sentinel-audit-local-tool-installer', accept: 'application/octet-stream' }, signal: AbortSignal.timeout(20 * 60 * 1000) });
  if (!response.ok || !response.body) throw new Error(`Descarga fallida: HTTP ${response.status}.`);
  const host = new URL(response.url).hostname.toLowerCase();
  if (!['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(host)) throw new Error('GitHub redirigió el artefacto fuera de los dominios de descarga permitidos.');
  const total = Number(response.headers.get('content-length')) || Number(asset.size);
  if (!total || total > MAX_RELEASE_BYTES) throw new Error('La descarga no informó un tamaño aceptable.');
  let received = 0;
  const hash = crypto.createHash('sha256');
  const meter = new Transform({ transform(chunk, encoding, callback) { received += chunk.length; if (received > total || received > MAX_RELEASE_BYTES) return callback(new Error('La descarga superó el tamaño declarado.')); hash.update(chunk); progress(job, 'DOWNLOADING', Math.min(94, received / total * 94), `Descargando ${asset.name}: ${Math.floor(received / 1024 / 1024)} / ${Math.ceil(total / 1024 / 1024)} MB`); callback(null, chunk); } });
  await pipeline(require('node:stream').Readable.fromWeb(response.body), meter, fs.createWriteStream(destination, { flags: 'wx', mode: 0o600 }));
  const actual = hash.digest('hex');
  if (received !== total || actual !== expectedDigest) { try { fs.rmSync(destination, { force: true }); } catch (_) {} throw new Error('No coincide el tamaño o el SHA-256 publicado por GitHub; archivo eliminado.'); }
}

function runProcess(command, args, options, onOutput) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    for (const stream of [child.stdout, child.stderr]) stream.on('data', (chunk) => { const text = chunk.toString('utf8'); output = (output + text).slice(-10000); if (onOutput) onOutput(text); });
    child.once('error', reject);
    child.once('close', (code) => code === 0 ? resolve(output) : reject(new Error(`${path.basename(command)} terminó con código ${code}: ${output.slice(-1200)}`)));
  });
}

async function extractZip(archive, destination, job) {
  progress(job, 'EXTRACTING', 95, 'Verificando y extrayendo archivos en la carpeta local de herramientas');
  // Fixed PowerShell code; file paths travel only through environment variables,
  // so release metadata cannot inject commands into the extractor.
  const command = "$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath $env:SENTINEL_AUDIT_ARCHIVE -DestinationPath $env:SENTINEL_AUDIT_DESTINATION -Force";
  await runProcess('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { env: { ...process.env, SENTINEL_AUDIT_ARCHIVE: archive, SENTINEL_AUDIT_DESTINATION: destination } });
}

function findExecutable(root, pattern) {
  const queue = [root]; let seen = 0;
  while (queue.length && seen++ < 10000) {
    const current = queue.shift(); let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch (_) { continue; }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory() && !entry.isSymbolicLink()) queue.push(full);
      else if (entry.isFile() && pattern.test(full.replace(/\\/g, '/'))) return full;
    }
  }
  return null;
}

function configToolAvailable(tool, binary) {
  const { tools } = loadConfig(); setToolOverride(tools, tool, binary);
  const { resolveTool } = require('../workflow/tooling');
  return resolveTool(tool, tools[tool]);
}

async function installGithubRelease(job, spec, target) {
  const { release, asset, digest } = await githubRelease(spec);
  job.version = String(release.tag_name || 'latest').replace(/^v/, '');
  progress(job, 'VERIFYING', 0, `Release oficial ${release.tag_name}; verificando archivo por SHA-256`);
  fs.mkdirSync(target, { recursive: false, mode: 0o700 });
  const archive = path.join(target, asset.name);
  await downloadAsset(job, asset, digest, archive);
  let binary;
  if (spec.kind === 'github-zip') {
    const extracted = path.join(target, 'payload'); fs.mkdirSync(extracted, { mode: 0o700 });
    await extractZip(archive, extracted, job);
    binary = findExecutable(extracted, spec.executable);
  } else binary = archive;
  if (!binary || !fs.existsSync(binary)) throw new Error('El archivo pasó SHA-256, pero no contiene el ejecutable esperado.');
  if (path.extname(binary).toLowerCase() !== '.exe' || fs.statSync(binary).size < 1024) throw new Error('El ejecutable extraído no pasó la verificación estructural.');
  try { fs.rmSync(archive, { force: true }); } catch (_) {}
  return binary;
}

async function installPythonTool(job, spec, target) {
  const response = await fetch(`https://pypi.org/pypi/${spec.package}/json`, { headers: { accept: 'application/json', 'user-agent': 'sentinel-audit-local-tool-installer' }, signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`PyPI respondió HTTP ${response.status}.`);
  const metadata = await response.json();
  const version = metadata && metadata.info && metadata.info.version;
  if (!/^\d+(?:\.\d+){1,3}(?:[a-z0-9.+-]+)?$/i.test(String(version || ''))) throw new Error('PyPI no devolvió una versión estable reconocible.');
  job.version = version;
  fs.mkdirSync(target, { recursive: false, mode: 0o700 });
  progress(job, 'INSTALLING', 8, `Creando un entorno Python aislado para ${spec.package} ${version}`);
  await runProcess('py.exe', ['-3', '-m', 'venv', target], { cwd: target });
  progress(job, 'DOWNLOADING', 14, `Descargando wheels oficiales de PyPI (${version})`);
  const scriptDir = path.join(target, 'Scripts');
  const python = path.join(scriptDir, 'python.exe');
  const pipArgs = ['-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--only-binary=:all:', '--progress-bar', 'raw', '--index-url', 'https://pypi.org/simple', `${spec.package}==${version}`];
  const output = await runProcess(python, pipArgs, { cwd: target, env: { ...process.env, PIP_REQUIRE_VIRTUALENV: 'true', PIP_NO_INPUT: '1' } }, (chunk) => {
    const matches = [...chunk.matchAll(/(?:^|\s)(\d{1,3})%/gm)];
    if (matches.length) { const fraction = Math.min(99, Math.max(...matches.map((m) => Number(m[1])))); progress(job, 'INSTALLING', 14 + fraction * 0.84, `Instalando ${spec.package}: ${fraction}%`); }
  });
  if (!/Successfully installed/i.test(output)) throw new Error('pip no confirmó la instalación del paquete.');
  const binary = path.join(scriptDir, spec.executableName);
  if (!fs.existsSync(binary) || !fs.statSync(binary).isFile()) throw new Error(`No se generó ${spec.executableName} en el entorno aislado.`);
  return binary;
}

async function install(job) {
  const spec = SPECS[job.tool];
  const target = path.join(STORE, `${job.tool}-${job.id}`);
  fs.mkdirSync(STORE, { recursive: true, mode: 0o700 });
  try {
    const binary = spec.kind === 'pypi' ? await installPythonTool(job, spec, target) : await installGithubRelease(job, spec, target);
    progress(job, 'REGISTERING', 99, 'Registrando la ruta aislada para Sentinel Audit');
    writeToolPath(job.tool, binary);
    const resolved = configToolAvailable(job.tool, binary);
    job.path = binary; job.blockedByHost = !!resolved.blockedByHost;
    progress(job, 'AVAILABLE', 100, job.blockedByHost ? 'Instalado y registrado; la política del host bloquea ejecutarlo en esta sesión.' : `Instalado, registrado y detectado (${job.version}).`);
  } catch (error) {
    try { fs.rmSync(target, { recursive: true, force: true }); } catch (_) {}
    throw error;
  }
}

function supportedTools() { return Object.keys(SPECS); }

module.exports = { startInstall, getJob, listJobs, supportedTools, configToolAvailable, STORE };
