'use strict';

const MAX_LINES = 500;
const MAX_BYTES = 256 * 1024;
let active = false;
let bytes = 0;
let rows = [];

function scrub(value) {
  return String(value == null ? '' : value)
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\b(gh[pousr]_[A-Za-z0-9_]{12,}|sntl_[A-Za-z0-9_-]{8,})\b/g, '[REDACTED_TOKEN]')
    .replace(/((?:api[_-]?key|secret|token|password)\s*[=:]\s*)[^\s,'"`]{6,}/gi, '$1[REDACTED]')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
}

function append(chunk) {
  if (!active) return;
  const text = scrub(Buffer.isBuffer(chunk) ? chunk.toString('utf8') : chunk);
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const row = { at: new Date().toISOString(), text: line.slice(0, 2000) };
    rows.push(row); bytes += Buffer.byteLength(row.text, 'utf8');
  }
  while (rows.length > MAX_LINES || bytes > MAX_BYTES) {
    const removed = rows.shift(); bytes -= Buffer.byteLength(removed.text, 'utf8');
  }
}

function beginSession() {
  rows = []; bytes = 0; active = true;
}
function endSession() { active = false; }
function getSessionLogs(limit = 120) { return rows.slice(-Math.max(1, Math.min(Number(limit) || 120, MAX_LINES))); }

function captureStream(stream) {
  if (!stream || typeof stream.write !== 'function') return () => {};
  const original = stream.write;
  stream.write = function captureChunk(chunk, ...args) { append(chunk); return original.call(this, chunk, ...args); };
  return () => { if (stream.write !== original) stream.write = original; };
}

module.exports = { beginSession, endSession, getSessionLogs, captureStream, scrub };
