'use strict';
/** Immutable-ish artifact store with containment and manifest integrity. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { redactValue } = require('./tooling');

function contained(root, ...parts) {
  const base = path.resolve(root);
  const candidate = path.join(...parts.map(String));
  const target = path.resolve(base, candidate);
  if (target !== base && !target.startsWith(base + path.sep)) throw new Error(`artifact path escapes execution directory: ${candidate}`);
  return target;
}

function writeJson(file, value, { overwrite = false } = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (!overwrite) {
    fs.writeFileSync(file, JSON.stringify(redactValue(value), null, 2), { flag: 'wx' });
    return file;
  }
  const temp = `${file}.tmp-${process.pid}-${crypto.randomUUID()}`;
  fs.writeFileSync(temp, JSON.stringify(redactValue(value), null, 2));
  fs.renameSync(temp, file);
  return file;
}

function hash(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function manifest(executionDir, status = {}) {
  const root = path.resolve(executionDir);
  const records = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch (_) { continue; }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) stack.push(full);
      else if (entry.name !== 'manifest.json') records.push({
        path: path.relative(root, full).replace(/\\/g, '/'),
        bytes: fs.statSync(full).size,
        sha256: hash(full),
      });
    }
  }
  records.sort((a, b) => a.path.localeCompare(b.path));
  const value = {
    schema: 'sentinel-audit-manifest/1.0.0',
    generatedAt: new Date().toISOString(),
    artifactCount: records.length,
    status,
    artifacts: records,
  };
  writeJson(contained(root, 'manifest.json'), value, { overwrite: true });
  return value;
}

function verifyManifest(executionDir) {
  const root = path.resolve(executionDir);
  const file = contained(root, 'manifest.json');
  if (!fs.existsSync(file)) return { ok: false, errors: ['manifest missing'] };
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  const errors = [];
  for (const item of saved.artifacts || []) {
    let full;
    try { full = contained(root, item.path); } catch (error) { errors.push(error.message); continue; }
    if (!fs.existsSync(full)) { errors.push(`missing: ${item.path}`); continue; }
    // manifest() never records a symlink, so one appearing afterwards means the
    // artifact was replaced by a link after the fact.  Its hash could still
    // match, which is precisely why the link has to be refused on its own.
    let stat = null;
    try { stat = fs.lstatSync(full); } catch (error) { errors.push(`unreadable: ${item.path}`); continue; }
    if (stat.isSymbolicLink()) { errors.push(`symlinked artifact: ${item.path}`); continue; }
    if (hash(full) !== item.sha256) errors.push(`hash mismatch: ${item.path}`);
  }
  return { ok: errors.length === 0, errors, manifest: saved };
}

function initExecution(baseDir, name, executionId) {
  const root = path.resolve(baseDir, name, executionId);
  fs.mkdirSync(root, { recursive: true });
  for (const dir of ['cloud', 'routing', 'specialists', 'correlation', 'report', 'state']) fs.mkdirSync(contained(root, dir), { recursive: true });
  return root;
}

module.exports = { contained, writeJson, manifest, verifyManifest, initExecution };
