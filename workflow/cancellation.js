'use strict';
/**
 * Interrupt handling.
 *
 * Without this, Ctrl+C killed the process wherever it happened: no expediente
 * update, no stage record, and a managed checkout left behind on disk.  The
 * operator was left with a worktree whose provenance could no longer be
 * established, and no record that the run was cancelled rather than finished.
 *
 * On the first interrupt the audit is marked CANCELLED, the worktree is removed
 * and the signal is re-emitted so the default handler still terminates the
 * process with the conventional exit code.  A second interrupt is not
 * intercepted: an operator who insists gets the immediate kill.
 */
const fs = require('fs');
const path = require('path');
const { contained } = require('./artifacts');

function markCancelled(executionDir, detail) {
  const root = path.resolve(executionDir);
  const file = contained(root, 'expediente.json');
  if (!fs.existsSync(file)) return false;
  const expediente = JSON.parse(fs.readFileSync(file, 'utf8'));
  expediente.pipelineStatus = 'CANCELLED';
  expediente.cancelledAt = new Date().toISOString();
  expediente.cancelReason = detail;
  const stages = expediente.stages && typeof expediente.stages === 'object' ? expediente.stages : {};
  for (const name of Object.keys(stages)) {
    if (stages[name] && stages[name].state === 'RUNNING') stages[name] = { state: 'CANCELLED', at: new Date().toISOString(), detail: 'interrupted by SIGINT' };
  }
  expediente.stages = stages;
  fs.writeFileSync(file, JSON.stringify(expediente, null, 2));
  return true;
}

/**
 * Returns a dispose function.  Disposing is required in tests and in embedded
 * use; leaving the listener attached would make one audit's interrupt cancel
 * every later audit in the same process.
 */
function installCancellation({ executionDir, controller = null, cleanup = null, log = () => {}, reraise = true } = {}) {
  let handled = false;
  const handler = () => {
    if (handled) return;
    handled = true;
    log('sentinel-audit: interrupted, recording CANCELLED and cleaning the worktree');
    if (controller) controller.abort();
    try { if (executionDir) markCancelled(executionDir, 'SIGINT'); } catch (error) { log(`sentinel-audit: could not record cancellation: ${error.message}`); }
    try { if (typeof cleanup === 'function') cleanup(); } catch (error) { log(`sentinel-audit: cleanup after interrupt failed: ${error.message}`); }
    process.removeListener('SIGINT', handler);
    if (reraise) process.kill(process.pid, 'SIGINT');
  };
  process.on('SIGINT', handler);
  return function dispose() { process.removeListener('SIGINT', handler); };
}

module.exports = { installCancellation, markCancelled };
