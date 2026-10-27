'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const KEYS_FILE = path.join(os.homedir(), '.sentinel', 'cloud_keys.json');
const LEGACY_TOKEN_FILE = path.join(os.homedir(), '.sentinel', 'cloud-token.txt');

const DISCLAIMER_TEXT = 
  'AVISO DE RESPONSABILIDAD: El usuario es el único responsable del uso de esta herramienta y de las ' +
  'decisiones de seguridad, fusión o despliegue tomadas con base en sus resultados. El desarrollador y ' +
  'los mantenedores no se hacen responsables de daños directos o indirectos, fallas de seguridad, ' +
  'código malicioso o vulnerabilidades no detectadas por Sentinel. Ningún motor de análisis estático o ' +
  'heurístico garantiza la detección del 100% de las amenazas.';

function maskToken(token) {
  if (!token) return '••••';
  const str = String(token).trim();
  if (str.length <= 8) return '••••' + str.slice(-2);
  const prefix = str.slice(0, 4);
  const suffix = str.slice(-4);
  const maskedMiddle = '•'.repeat(Math.min(16, Math.max(8, str.length - 8)));
  return `${prefix}_${maskedMiddle}_${suffix}`;
}

function ensureStore() {
  const dir = path.dirname(KEYS_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  if (!fs.existsSync(KEYS_FILE)) {
    let initialKeys = [];
    if (fs.existsSync(LEGACY_TOKEN_FILE)) {
      try {
        const legacy = fs.readFileSync(LEGACY_TOKEN_FILE, 'utf8').trim();
        if (legacy) {
          initialKeys.push({
            id: 'key-1',
            name: 'Clave 1 (Default)',
            token: legacy,
            addedAt: new Date().toISOString()
          });
        }
      } catch (_) {}
    }
    const initialData = { keys: initialKeys };
    fs.writeFileSync(KEYS_FILE, JSON.stringify(initialData, null, 2), 'utf8');
    return initialData;
  }

  try {
    const raw = fs.readFileSync(KEYS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return { keys: [] };
  }
}

function saveStore(data) {
  const dir = path.dirname(KEYS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function listKeys() {
  const store = ensureStore();
  return (store.keys || []).map((k, idx) => ({
    index: idx + 1,
    id: k.id,
    name: k.name || `Clave ${idx + 1}`,
    maskedToken: maskToken(k.token),
    addedAt: k.addedAt || null
  }));
}

function getRawKeys() {
  const store = ensureStore();
  return store.keys || [];
}

function getKey(idOrIndex) {
  const store = ensureStore();
  const keys = store.keys || [];
  if (typeof idOrIndex === 'number') {
    return keys[idOrIndex - 1] || null;
  }
  return keys.find(k => k.id === idOrIndex || k.name === idOrIndex) || null;
}

function addKey(token, customName) {
  if (!token || typeof token !== 'string' || token.trim().length < 6) {
    throw new Error('El token de Cloud ingresado no es válido o es demasiado corto.');
  }
  const clean = token.trim();
  const store = ensureStore();
  const nextNum = (store.keys || []).length + 1;
  const newKey = {
    id: `key-${Date.now()}`,
    name: customName && customName.trim() ? customName.trim() : `Clave ${nextNum}`,
    token: clean,
    addedAt: new Date().toISOString()
  };
  store.keys = store.keys || [];
  store.keys.push(newKey);
  saveStore(store);

  // También sincronizar legado cloud-token.txt si es la primera
  if (store.keys.length === 1) {
    try { fs.writeFileSync(LEGACY_TOKEN_FILE, clean, 'utf8'); } catch (_) {}
  }

  return {
    id: newKey.id,
    name: newKey.name,
    maskedToken: maskToken(newKey.token)
  };
}

function revokeKey(idOrIndex) {
  const store = ensureStore();
  const keys = store.keys || [];
  let removed = null;

  if (typeof idOrIndex === 'number') {
    const idx = idOrIndex - 1;
    if (idx >= 0 && idx < keys.length) {
      removed = keys.splice(idx, 1)[0];
    }
  } else {
    const idx = keys.findIndex(k => k.id === idOrIndex || k.name === idOrIndex);
    if (idx !== -1) {
      removed = keys.splice(idx, 1)[0];
    }
  }

  if (!removed) {
    throw new Error('Clave no encontrada para revocar.');
  }

  saveStore(store);

  // Si se borró la clave que coincidía con cloud-token.txt, actualizar o borrar
  if (fs.existsSync(LEGACY_TOKEN_FILE)) {
    try {
      if (store.keys.length > 0) {
        fs.writeFileSync(LEGACY_TOKEN_FILE, store.keys[0].token, 'utf8');
      } else {
        fs.unlinkSync(LEGACY_TOKEN_FILE);
      }
    } catch (_) {}
  }

  return {
    removed,
    warning: 'ADVERTENCIA: La clave ha sido eliminada únicamente de esta máquina local. ' +
             'Para invalidarla permanentemente y evitar cualquier uso futuro, debes revocarla ' +
             'desde el panel de administración de Sentinel Cloud.'
  };
}

module.exports = {
  KEYS_FILE,
  DISCLAIMER_TEXT,
  maskToken,
  listKeys,
  getRawKeys,
  getKey,
  addKey,
  revokeKey
};
