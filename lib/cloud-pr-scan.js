'use strict';

const { randomUUID } = require('node:crypto');

function resolvedBaseUrl(env = process.env) {
  const raw = String(env.SENTINEL_CLOUD_URL || '').trim();
  if (!raw) throw new Error('Configura SENTINEL_CLOUD_URL para usar Pulsos de Sentinel Cloud.');
  let url;
  try { url = new URL(raw); } catch { throw new Error('SENTINEL_CLOUD_URL no es una URL válida.'); }
  const loopback = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('Se requiere HTTPS para enviar la API key de Sentinel Cloud.');
  }
  return url.toString().replace(/\/+$/, '');
}

async function responseError(response) {
  try {
    const body = await response.json();
    return typeof body.error === 'string' ? body.error : `Sentinel Cloud respondió HTTP ${response.status}.`;
  } catch {
    return `Sentinel Cloud respondió HTTP ${response.status}.`;
  }
}

function redactToken(token, message) {
  return String(message || 'Sentinel Cloud no completó el análisis.').split(token).join('[redacted]');
}

async function fetchCloudPRScan({ repo, prNumber, expectedHeadSha, token, baseUrl, fetchImpl = globalThis.fetch, timeoutMs = 180000, onProgress }) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error('Repositorio inválido; usa owner/repo.');
  if (!Number.isInteger(prNumber) || prNumber < 1) throw new Error('Número de PR inválido.');
  if (!/^[0-9a-f]{40}$/i.test(expectedHeadSha)) throw new Error('GitHub no devolvió el SHA completo del head del PR.');
  if (typeof token !== 'string' || token.length < 6) throw new Error('La API key de Sentinel Cloud no es válida.');
  const base = resolvedBaseUrl(baseUrl ? { SENTINEL_CLOUD_URL: baseUrl } : process.env);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
    const capabilities = await fetchImpl(`${base}/api/auth/capabilities`, { headers, signal: controller.signal });
    if (!capabilities.ok) throw new Error(redactToken(token, await responseError(capabilities)));
    const capabilityBody = await capabilities.json();
    if (!capabilityBody || !capabilityBody.capabilities || capabilityBody.capabilities.remote_scan !== true) {
      throw new Error('El plan de esta clave no tiene habilitados los escaneos Cloud.');
    }
    if (onProgress) onProgress({ stage: 'AUTH', state: 'COMPLETE', detail: capabilityBody.planLabel ? `plan ${capabilityBody.planLabel}` : 'clave validada' });
    if (onProgress) onProgress({ stage: 'ENGINE', state: 'RUNNING', detail: 'Cloud analiza el PR completo; se consumirá un pulso' });

    const response = await fetchImpl(`${base}/api/scan/pr`, {
      method: 'POST',
      headers: {
        ...headers,
        'Content-Type': 'application/json',
        'Idempotency-Key': `sentinel-audit-${randomUUID()}`,
      },
      body: JSON.stringify({ repo: repo.toLowerCase(), prNumber, expectedHeadSha }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(redactToken(token, await responseError(response)));
    const data = await response.json();
    if (!data || !data.level1 || (data.level3 && data.level3.samples !== undefined && !Array.isArray(data.level3.samples))) {
      throw new Error('Sentinel Cloud devolvió una respuesta de escaneo inválida.');
    }
    if (onProgress) onProgress({ stage: 'ENGINE', state: 'COMPLETE', detail: `motor Cloud ${data.engine_version || 'desconocido'}` });
    return data;
  } catch (error) {
    if (error instanceof Error && (error.message.includes('SENTINEL_CLOUD_URL') || error.message.includes('HTTPS') || error.message.includes('inválid') || error.message.includes('habilitados') || error.message.includes('[redacted]'))) throw error;
    throw new Error(redactToken(token, error instanceof Error ? error.message : error));
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { resolvedBaseUrl, fetchCloudPRScan };
