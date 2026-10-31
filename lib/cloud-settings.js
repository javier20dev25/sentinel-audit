'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const FILE = path.join(os.homedir(), '.sentinel-audit', 'cloud-settings.json');
const DEFAULT_ENDPOINT = 'https://sentinel-psi-nine.vercel.app';

function validateEndpoint(value) {
  let parsed;
  try { parsed = new URL(String(value || '').trim()); }
  catch (_) { throw Object.assign(new Error('Ingresa una URL completa para Sentinel Cloud.'), { status: 400 }); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname.toLowerCase());
  if (parsed.username || parsed.password || parsed.search || parsed.hash || !['https:', 'http:'].includes(parsed.protocol) || (parsed.protocol === 'http:' && !loopback)) {
    throw Object.assign(new Error('La URL debe usar HTTPS; HTTP solo se permite para localhost. No incluyas credenciales, query ni fragmento.'), { status: 400 });
  }
  return parsed.toString().replace(/\/+$/, '');
}

function resolveEndpoint({ url = null, env = process.env.SENTINEL_CLOUD_URL } = {}) {
  const candidate = String(url || '').trim() || String(env || '').trim() || DEFAULT_ENDPOINT;
  return validateEndpoint(candidate);
}

function read() {
  try {
    const value = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (value.schema !== 'sentinel-audit-cloud-settings/1.0' || typeof value.enabled !== 'boolean') throw new Error('Formato de configuración Cloud no reconocido.');
    return { enabled: value.enabled, url: value.url ? validateEndpoint(value.url) : null };
  } catch (error) {
    if (error.code === 'ENOENT') return { enabled: null, url: null };
    throw new Error(`No se pudo leer la configuración local de Pulse: ${error.message}`);
  }
}

function save({ enabled, url }) {
  if (typeof enabled !== 'boolean') throw Object.assign(new Error('Indica si Pulse queda activado o desactivado.'), { status: 400 });
  const current = read();
  const provided = url == null ? '' : String(url).trim();
  const endpoint = provided ? validateEndpoint(provided) : current.url || resolveEndpoint();
  const document = { schema: 'sentinel-audit-cloud-settings/1.0', enabled, url: endpoint, updatedAt: new Date().toISOString() };
  fs.mkdirSync(path.dirname(FILE), { recursive: true, mode: 0o700 });
  const temp = `${FILE}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, FILE);
  try { fs.chmodSync(FILE, 0o600); } catch (_) {}
  return { enabled: document.enabled, url: document.url, updatedAt: document.updatedAt };
}

module.exports = { FILE, DEFAULT_ENDPOINT, validateEndpoint, resolveEndpoint, read, save };
