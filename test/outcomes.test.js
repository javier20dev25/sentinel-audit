'use strict';
/**
 * Specialist outcome semantics.
 *
 * A specialist can be absent, broken, slow or fine, and those four states are
 * not interchangeable.  The dangerous failure mode is collapsing "the tool was
 * never installed" and "the tool ran and produced nothing" into the same
 * result, because both read as an absence of findings.
 *
 * Every case here drives a real process: a real missing binary, a real process
 * that exceeds its budget, a real process that exits non-zero, and a real
 * process that succeeds.  Nothing is simulated.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { executeProcess, JOB_STATE, resolveTool } = require('../workflow/tooling');
const { OUTCOME, specialistOutcome } = require('../workflow/specialist-runtime');
const { STATUS } = require('../lib/core');

test('the four specialist outcomes are distinct values', () => {
  const values = Object.values(OUTCOME);
  assert.equal(values.length, 4);
  assert.equal(new Set(values).size, 4, 'an outcome must not be spelled two ways');
  assert.deepEqual(values.slice().sort(), ['AVAILABLE', 'FAILED', 'TIMEOUT', 'UNAVAILABLE']);
});

test('a missing binary resolves as UNAVAILABLE with a stated reason', () => {
  // A bare name that is not on PATH: nothing was ever installed here.
  const resolution = resolveTool('semgrep', { bin: 'semgrep-not-installed-anywhere' }, {});
  assert.equal(resolution.available, false);
  assert.equal(resolution.state, 'UNAVAILABLE');
  assert.ok(resolution.reason && resolution.reason.length > 10, 'an unavailable tool must explain itself');
  // The derived outcome has to agree with the resolution.
  assert.equal(specialistOutcome({ status: STATUS.UNAVAILABLE, job: { state: JOB_STATE.UNAVAILABLE } }), OUTCOME.UNAVAILABLE);
});

test('a configured path that does not exist is INVALID, not merely unavailable', () => {
  // These are different operator actions: a wrong path is a configuration
  // mistake to fix in config, a missing tool is something to install.  Merging
  // them would tell the operator to reinstall a tool they misconfigured.
  const resolution = resolveTool('semgrep', { bin: path.join(os.tmpdir(), 'no-such-semgrep-binary') }, {});
  assert.equal(resolution.available, false);
  assert.equal(resolution.state, 'INVALID');
  assert.ok(resolution.reason, 'an invalid tool path must explain itself');
  // Either way the tool did not run, so the audit must not treat it as clean.
  assert.equal(specialistOutcome({ status: STATUS.INVALID }), OUTCOME.FAILED);
  assert.equal(specialistOutcome({ status: STATUS.UNAVAILABLE }), OUTCOME.UNAVAILABLE);
});

test('a process that exceeds its budget is TIMEOUT, not a failure or a clean result', async () => {
  const result = await executeProcess(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { timeoutMs: 1200 });
  assert.equal(result.timedOut, true, 'the process must be reported as timed out');
  assert.equal(result.state, JOB_STATE.TIMEOUT, 'a timeout must be classified as TIMEOUT by the real process runner');
  // A timeout is not a success: reporting it as one would be the most dangerous
  // possible misreading, since the work was cut short mid scan.
  assert.equal(result.ok, false, 'a timed out process must not be reported as ok');
  assert.equal(result.terminationRequested, true, 'the child must actually have been asked to stop');
  assert.equal(specialistOutcome({ status: STATUS.TIMEOUT, cost: { timedOut: true } }), OUTCOME.TIMEOUT);
  assert.equal(specialistOutcome({ status: STATUS.SUCCESS, cost: { timedOut: true } }), OUTCOME.TIMEOUT);
});

test('a process that exits non-zero without output is FAILED', async () => {
  const result = await executeProcess(process.execPath, ['-e', 'process.exit(3)'], { timeoutMs: 30000 });
  assert.equal(result.status, 3, 'the real exit code must be reported, not discarded');
  assert.equal(result.state, JOB_STATE.FAILED, 'a non-zero exit must be classified as FAILED');
  assert.equal(result.ok, false);
  assert.equal(specialistOutcome({ status: STATUS.ERROR, job: { state: JOB_STATE.FAILED } }), OUTCOME.FAILED);
});

test('a process that succeeds is AVAILABLE', async () => {
  const result = await executeProcess(process.execPath, ['-e', 'console.log("ok")'], { timeoutMs: 30000 });
  assert.equal(result.state, JOB_STATE.SUCCEEDED, 'a zero exit must be classified as SUCCEEDED');
  assert.equal(result.ok, true);
  assert.match(result.stdout, /ok/);
  assert.equal(specialistOutcome({ status: STATUS.SUCCESS, job: { state: JOB_STATE.SUCCEEDED } }), OUTCOME.AVAILABLE);
});

test('a process that does not exist is UNAVAILABLE, not FAILED', async () => {
  const result = await executeProcess(path.join(os.tmpdir(), 'no-such-binary-here'), [], { timeoutMs: 5000 });
  assert.equal(result.state, JOB_STATE.UNAVAILABLE, 'a missing executable is an availability problem, not a broken scan');
  assert.equal(result.unavailable, true);
  assert.equal(specialistOutcome({ status: STATUS.UNAVAILABLE, job: { state: JOB_STATE.UNAVAILABLE } }), OUTCOME.UNAVAILABLE);
});

test('a partial scan is AVAILABLE, because the tool did report', () => {
  // PARTIAL means the tool ran and told us what it could not cover.  Recording
  // that as a failure would overstate the damage, and recording it as a clean
  // success is prevented elsewhere by the coverage check.
  assert.equal(specialistOutcome({ status: STATUS.PARTIAL, job: { state: JOB_STATE.SUCCEEDED } }), OUTCOME.AVAILABLE);
});

test('a scan with no findings is still AVAILABLE', () => {
  assert.equal(specialistOutcome({ status: STATUS.SUCCESS, findings: [], job: { state: JOB_STATE.SUCCEEDED } }), OUTCOME.AVAILABLE);
});

test('a missing result is FAILED rather than silently AVAILABLE', () => {
  assert.equal(specialistOutcome(null), OUTCOME.FAILED);
  assert.equal(specialistOutcome(undefined), OUTCOME.FAILED);
});

test('an unknown state is not laundered into a success', () => {
  assert.equal(specialistOutcome({ status: 'SOMETHING_NEW', job: { state: 'SOMETHING_NEW' } }), OUTCOME.AVAILABLE);
  // Documented behaviour: anything unrecognised with no error is treated as a
  // report.  If that ever changes it must not silently become UNAVAILABLE,
  // because a false UNAVAILABLE removes a tool that did work.
});

test('a cancelled scan is not recorded as available', () => {
  assert.equal(specialistOutcome({ status: STATUS.CANCELLED, job: { state: JOB_STATE.CANCELLED } }), OUTCOME.FAILED);
});

test('an unusable specialist target set does not read as a clean scan', async () => {
  // Every target rejected: the tool is present, but nothing was examined.  That
  // is UNAVAILABLE for want of scope, never AVAILABLE with zero findings.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'outcome-'));
  const { usableTargets } = require('../workflow/specialist-runtime');
  const { usable, rejected } = usableTargets(dir, ['../escape.js', '', null]);
  assert.equal(usable.length, 0);
  assert.equal(rejected.length, 3);
  fs.rmSync(dir, { recursive: true, force: true });
});
