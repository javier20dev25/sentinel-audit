'use strict';

const fs = require('fs');
const path = require('path');

function cleanupRun(executionDir) {
  const outRoot = path.resolve(__dirname, '..', 'out');
  const runDir = path.resolve(executionDir);
  const prefix = outRoot + path.sep;
  if (!runDir.startsWith(prefix) || !fs.existsSync(runDir) || !fs.statSync(runDir).isDirectory()) {
    throw new Error('cleanup target must be an existing execution directory under sentinel-audit/out');
  }
  if (fs.lstatSync(runDir).isSymbolicLink()) throw new Error('cleanup target cannot be a symbolic link');
  const realOut = fs.realpathSync(outRoot);
  const realRun = fs.realpathSync(runDir);
  if (!realRun.startsWith(realOut + path.sep)) throw new Error('resolved cleanup target escapes sentinel-audit/out');
  const db = path.join(runDir, 'codeql-db');
  const cleanupErrors = [];
  const removed = [];
  if (fs.existsSync(db)) {
    const st = fs.lstatSync(db);
    if (st.isSymbolicLink()) cleanupErrors.push('refused to follow codeql-db symlink');
    else {
      try { fs.rmSync(db, { recursive: true, force: false }); removed.push('codeql-db'); }
      catch (e) { cleanupErrors.push(`codeql-db: ${e.message}`); }
    }
  }
  const result = {
    cleanupStatus: cleanupErrors.length ? 'FAILED' : 'SUCCESS',
    cleanupErrors,
    removed,
    retainedEvidence: true,
    cleanedAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(runDir, 'cleanup.json'), JSON.stringify(result, null, 2));
  return result;
}

module.exports = { cleanupRun };
