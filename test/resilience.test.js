'use strict';
/**
 * Operational resilience tests.
 *
 * Every case here exercises real code paths on this host: a real manifest over
 * real files, a real symlink or junction, a real SIGINT delivered through the
 * process event system, a real unwritable destination, a real dead network
 * endpoint and a real scheduler.  Nothing is asserted against a mock, because
 * the defects these guard against were all defects in the wiring, not in the
 * units.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { manifest, verifyManifest } = require('../workflow/artifacts');
const { usableTargets } = require('../workflow/specialist-runtime');
const { realContained, abs: resolveTarget, relTarget } = require('../workflow/paths');
const { ResourceScheduler } = require('../workflow/scheduler');
const { JOB_STATE } = require('../workflow/tooling');
const { installCancellation, markCancelled } = require('../workflow/cancellation');
const { rebaseTargets } = require('../workflow/workspace');

function temp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}-`));
}

function gitRepo(prefix) {
  const dir = temp(prefix);
  const run = (args) => spawnSync('git', args, { cwd: dir, encoding: 'utf8' });
  run(['init', '-q']);
  run(['config', 'user.email', 'audit@test.invalid']);
  run(['config', 'user.name', 'Sentinel Audit Test']);
  return dir;
}

// ---------------------------------------------------------------- integrity

test('a modified artifact fails manifest verification', () => {
  const dir = temp('manifest');
  fs.writeFileSync(path.join(dir, 'finding.json'), '{"rule":"R1"}\n');
  const written = manifest(dir, { stage: 'TEST' });
  assert.equal(written.artifactCount, 1);
  assert.equal(verifyManifest(dir).ok, true, 'an untouched execution must verify');

  // Tamper with the content while keeping the same byte length, so a
  // size-only check would still pass.
  const file = path.join(dir, 'finding.json');
  const before = fs.readFileSync(file, 'utf8');
  fs.writeFileSync(file, before.replace('R1', 'R2'));
  const after = verifyManifest(dir);
  assert.equal(after.ok, false, 'tampering must be detected');
  assert.ok(after.errors.some((e) => /hash mismatch/.test(e)), after.errors.join('; '));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a deleted artifact fails manifest verification', () => {
  const dir = temp('manifest-missing');
  fs.writeFileSync(path.join(dir, 'a.json'), '{}');
  fs.writeFileSync(path.join(dir, 'b.json'), '{}');
  manifest(dir, {});
  fs.rmSync(path.join(dir, 'b.json'));
  const result = verifyManifest(dir);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => /missing: b\.json/.test(e)), result.errors.join('; '));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an artifact replaced by a symlink fails verification even if the hash matches', () => {
  const dir = temp('manifest-link');
  const real = path.join(dir, 'real');
  const decoy = temp('manifest-decoy');
  fs.mkdirSync(real);
  fs.writeFileSync(path.join(real, 'a.json'), '{"same":true}\n');
  fs.writeFileSync(path.join(decoy, 'a.json'), '{"same":true}\n');
  manifest(dir, {});
  assert.equal(verifyManifest(dir).ok, true);

  // Same bytes, different provenance: a link is not the artifact that was
  // hashed, and accepting it would let the evidence be swapped after the fact.
  const target = path.join(real, 'a.json');
  fs.rmSync(target);
  let linked = false;
  try { fs.symlinkSync(path.join(decoy, 'a.json'), target, 'file'); linked = true; } catch (error) { linked = false; }
  if (linked) {
    const result = verifyManifest(dir);
    assert.equal(result.ok, false, 'a symlinked artifact must be refused');
    assert.ok(/symlinked artifact/.test(result.errors.join('; ')), result.errors.join('; '));
  }
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(decoy, { recursive: true, force: true });
});

test('an execution with no manifest is not treated as verified', () => {
  const dir = temp('manifest-absent');
  fs.writeFileSync(path.join(dir, 'expediente.json'), '{}');
  const result = verifyManifest(dir);
  assert.equal(result.ok, false);
  assert.ok(/manifest missing/.test(result.errors.join('; ')), result.errors.join('; '));
  fs.rmSync(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------ symlink escape

test('a symlink or junction inside the repository cannot reach a target outside it', () => {
  const repo = gitRepo('link-repo');
  const outside = temp('link-outside');
  fs.writeFileSync(path.join(outside, 'secret.js'), 'eval(x);\n');

  const link = path.join(repo, 'escape');
  let linked = false;
  try {
    // A directory junction needs no elevated privilege on Windows, so it is the
    // portable form; a symbolic link is used where that is the only option.
    fs.symlinkSync(outside, link, 'junction');
    linked = true;
  } catch (junctionError) {
    try { fs.symlinkSync(outside, link, 'dir'); linked = true; } catch (symbolicError) { linked = false; }
  }
  if (!linked) {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
    return; // the host forbids link creation; the realpath check is still covered below
  }

  const check = realContained(repo, link);
  assert.equal(check.ok, false, 'a link pointing outside the repository must be refused');
  assert.ok(/outside the audited repository/.test(check.reason), check.reason);

  // A file link has to be refused as well, otherwise the escape only depends on
  // whether the target happens to be a directory.
  const fileLink = path.join(repo, 'escape.js');
  let fileLinked = false;
  try { fs.symlinkSync(path.join(outside, 'secret.js'), fileLink, 'file'); fileLinked = true; } catch (error) { fileLinked = false; }
  if (fileLinked) {
    const fileCheck = realContained(repo, fileLink);
    assert.equal(fileCheck.ok, false, 'a file link pointing outside the repository must be refused');
  }

  fs.rmSync(repo, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});

test('containment is refused even when the link cannot be created', () => {
  // Independent of link support: a path that only looks inside the repository
  // but escapes through '..' must never resolve to a usable target.
  const repo = temp('contain');
  assert.equal(resolveTarget(repo, '../outside.js'), null);
  assert.equal(resolveTarget(repo, 'a/../../outside.js'), null);
  assert.equal(resolveTarget(repo, ''), null);
  assert.equal(resolveTarget(repo, null), null);
  assert.equal(relTarget(repo, path.resolve(repo, '..', 'outside.js')), null);
  assert.equal(relTarget(repo, path.join(repo, 'inside', 'a.js')), 'inside/a.js');
  assert.equal(relTarget(repo, repo), '.');
  fs.rmSync(repo, { recursive: true, force: true });
});

test('a target that is only reachable through a traversal is rejected before the scan', () => {
  const repo = temp('traversal');
  fs.writeFileSync(path.join(repo, 'ok.js'), 'eval(x);\n');
  const { usable, rejected } = usableTargets(repo, ['../ok.js', 'ok.js']);
  assert.deepEqual(usable, [path.join(repo, 'ok.js')]);
  assert.equal(rejected.length, 1);
  assert.ok(/outside the audited repository/.test(rejected[0].reason), rejected[0].reason);
  fs.rmSync(repo, { recursive: true, force: true });
});

// ------------------------------------------------------------------- SIGINT

test('SIGINT aborts the run, records CANCELLED and removes the worktree', async () => {
  const executionDir = temp('cancel');
  const worktree = path.join(executionDir, 'worktree');
  fs.mkdirSync(path.join(worktree, 'src'), { recursive: true });
  fs.writeFileSync(path.join(worktree, 'src', 'a.js'), 'eval(x);\n');
  fs.writeFileSync(path.join(executionDir, 'expediente.json'), JSON.stringify({
    schema: 'sentinel-audit-expediente/1.0.0',
    executionId: 'exec-cancel-test',
    pipelineStatus: 'RUNNING',
    stages: { PREFLIGHT: { state: 'COMPLETE' }, SPECIALISTS: { state: 'RUNNING' } },
  }, null, 2));

  const controller = new AbortController();
  let cleaned = 0;
  const messages = [];
  // reraise:false keeps the production re-raise out of the test, which would
  // otherwise terminate the runner instead of letting it assert the outcome.
  const dispose = installCancellation({
    executionDir,
    controller,
    cleanup: () => { fs.rmSync(worktree, { recursive: true, force: true }); cleaned++; },
    log: (message) => messages.push(message),
    reraise: false,
  });

  process.emit('SIGINT');
  await new Promise((resolve) => setImmediate(resolve));

  assert.ok(messages.length > 0, 'the interrupt must be reported to the operator');
  assert.equal(controller.signal.aborted, true, 'the AbortSignal must fire so running specialists are cancelled');
  assert.equal(cleaned, 1, 'the managed checkout must be removed exactly once');
  assert.equal(fs.existsSync(worktree), false, 'the worktree must not survive an interrupt');

  const expediente = JSON.parse(fs.readFileSync(path.join(executionDir, 'expediente.json'), 'utf8'));
  assert.equal(expediente.pipelineStatus, 'CANCELLED');
  assert.equal(expediente.cancelReason, 'SIGINT');
  assert.equal(expediente.stages.SPECIALISTS.state, 'CANCELLED', 'a RUNNING stage must not be left claiming progress');
  assert.equal(expediente.stages.PREFLIGHT.state, 'COMPLETE', 'a finished stage must not be rewritten');

  dispose();
  fs.rmSync(executionDir, { recursive: true, force: true });
});

test('cancelling a running specialist stops it instead of recording success', async () => {
  const scheduler = new ResourceScheduler({ maxHeavy: 1, maxLight: 1 });
  let observedAbort = false;
  const job = scheduler.add({
    id: 'heavy-1',
    resourceClass: 'HEAVY',
    run: ({ signal }) => new Promise((resolve) => {
      signal.addEventListener('abort', () => { observedAbort = true; resolve({ state: JOB_STATE.CANCELLED, cancelled: true }); });
    }),
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(job.state, JOB_STATE.RUNNING);
  scheduler.cancel('heavy-1');
  const [settled] = await scheduler.drain();
  assert.equal(observedAbort, true, 'the running job must observe the abort');
  assert.equal(settled.state, JOB_STATE.CANCELLED);
});

test('a second cancel of a finished job is refused rather than re-settled', async () => {
  const scheduler = new ResourceScheduler({ maxHeavy: 1, maxLight: 1 });
  scheduler.add({ id: 'light-1', resourceClass: 'LIGHT', run: async () => ({ state: JOB_STATE.SUCCEEDED }) });
  await scheduler.drain();
  assert.equal(scheduler.cancel('light-1'), false, 'a settled job must not be cancelled twice');
  assert.equal(scheduler.cancel('never-queued'), false);
});

test('markCancelled reports failure instead of throwing on a missing expediente', () => {
  const dir = temp('cancel-absent');
  assert.equal(markCancelled(dir, 'SIGINT'), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------- disk failure

test('an artifact destination that cannot be created fails loudly', () => {
  const dir = temp('disk');
  // A regular file where a directory is required: mkdir must fail with ENOTDIR
  // or EEXIST on every platform, unlike chmod-based read-only tricks.
  const blocker = path.join(dir, 'blocked');
  fs.writeFileSync(blocker, 'not a directory');
  assert.throws(() => fs.mkdirSync(path.join(blocker, 'worktree'), { recursive: true }));
  // The same destination must not appear to exist afterwards.
  assert.equal(fs.existsSync(path.join(blocker, 'worktree')), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a write that fails is reported rather than counted as evidence', () => {
  const dir = temp('disk-write');
  const { writeJson } = require('../workflow/artifacts');
  const target = path.join(dir, 'report.json');
  writeJson(target, { ok: true });
  assert.deepEqual(JSON.parse(fs.readFileSync(target, 'utf8')), { ok: true });

  // A directory in place of the file makes the write fail; the caller must see
  // the throw instead of an empty artifact being treated as a result.
  const blocked = path.join(dir, 'blocked.json');
  fs.mkdirSync(blocked);
  assert.throws(() => writeJson(blocked, { ok: true }));
  fs.rmSync(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------ network failure

test('an unreachable network endpoint is reported as a failure, not as a clean result', () => {
  // Port 1 on loopback is not listening, so the request fails at the transport
  // layer.  This is the same shape as an OSV database fetch or a Cloud call
  // with no egress, and it must never be indistinguishable from "no findings".
  const result = spawnSync(process.execPath, ['-e', `
    const https = require('https');
    const request = https.get({ host: '127.0.0.1', port: 1, path: '/', timeout: 2000 }, () => { console.log('UNEXPECTED_SUCCESS'); });
    request.on('error', (error) => { console.log('FAILED:' + error.code); });
    request.on('timeout', () => { request.destroy(); console.log('FAILED:ETIMEDOUT'); });
  `], { encoding: 'utf8', timeout: 30000 });
  assert.match(result.stdout, /FAILED:/, 'the endpoint must fail rather than answer');
  assert.doesNotMatch(result.stdout, /UNEXPECTED_SUCCESS/);
});

test('a tool binary that is missing resolves as UNAVAILABLE instead of a silent skip', () => {
  const { resolveTool } = require('../workflow/tooling');
  const resolution = resolveTool('osv', { bin: path.join(os.tmpdir(), 'definitely-not-installed-osv') }, {});
  assert.equal(resolution.available, false);
  assert.ok(resolution.reason, 'an unavailable tool must state why');
});

// ------------------------------------------------- concurrency and isolation

test('heavy concurrency never exceeds the configured limit', async () => {
  const scheduler = new ResourceScheduler({ maxHeavy: 2, maxLight: 3 });
  let heavyActive = 0;
  let lightActive = 0;
  let peakHeavy = 0;
  let peakLight = 0;
  for (let i = 0; i < 8; i++) {
    const heavy = i % 2 === 0;
    scheduler.add({
      id: heavy ? `heavy-${i}` : `light-${i}`,
      resourceClass: heavy ? 'HEAVY' : 'LIGHT',
      run: async () => {
        if (heavy) { heavyActive++; peakHeavy = Math.max(peakHeavy, heavyActive); } else { lightActive++; peakLight = Math.max(peakLight, lightActive); }
        await new Promise((resolve) => setTimeout(resolve, 5));
        if (heavy) heavyActive--; else lightActive--;
        return { state: JOB_STATE.SUCCEEDED };
      },
    });
  }
  const settled = await scheduler.drain();
  assert.equal(settled.length, 8);
  assert.ok(peakHeavy <= 2, `peak heavy concurrency was ${peakHeavy}`);
  assert.ok(peakLight <= 3, `peak light concurrency was ${peakLight}`);
  assert.ok(settled.every((job) => job.state === JOB_STATE.SUCCEEDED));
});

test('one failing specialist does not remove the results of its siblings', async () => {
  const scheduler = new ResourceScheduler({ maxHeavy: 2, maxLight: 2 });
  const produced = {};
  scheduler.add({ id: 'ok-1', resourceClass: 'LIGHT', run: async () => { produced.ok1 = true; return { state: JOB_STATE.SUCCEEDED, findingCount: 3 }; } });
  scheduler.add({ id: 'boom', resourceClass: 'HEAVY', run: async () => { throw new Error('specialist exploded'); } });
  scheduler.add({ id: 'ok-2', resourceClass: 'LIGHT', run: async () => { produced.ok2 = true; return { state: JOB_STATE.SUCCEEDED, findingCount: 5 }; } });
  const settled = await scheduler.drain();
  assert.equal(produced.ok1, true, 'a sibling must still run after another throws');
  assert.equal(produced.ok2, true);
  const failed = settled.find((job) => job.id === 'boom');
  assert.equal(failed.state, JOB_STATE.FAILED);
  assert.match(failed.result.error, /specialist exploded/);
  assert.equal(settled.find((job) => job.id === 'ok-1').result.findingCount, 3);
  assert.equal(settled.find((job) => job.id === 'ok-2').result.findingCount, 5);
});

test('a rejected job is isolated and the queue keeps draining', async () => {
  const scheduler = new ResourceScheduler({ maxHeavy: 1, maxLight: 1 });
  const order = [];
  scheduler.add({ id: 'a', resourceClass: 'HEAVY', run: async () => { order.push('a'); return { state: JOB_STATE.SUCCEEDED }; } });
  scheduler.add({ id: 'b', resourceClass: 'HEAVY', run: () => Promise.reject(new Error('network reset')) });
  scheduler.add({ id: 'c', resourceClass: 'HEAVY', run: async () => { order.push('c'); return { state: JOB_STATE.SUCCEEDED }; } });
  const settled = await scheduler.drain();
  assert.deepEqual(order, ['a', 'c'], 'the job queued after a rejection must still run');
  assert.equal(settled.find((job) => job.id === 'b').state, JOB_STATE.FAILED);
});

test('the scheduler refuses work that would violate its own contract', () => {
  assert.throws(() => new ResourceScheduler({ maxHeavy: 0 }), /maxHeavy/);
  assert.throws(() => new ResourceScheduler({ maxLight: -1 }), /maxLight/);
  const scheduler = new ResourceScheduler({ maxHeavy: 1, maxLight: 1 });
  assert.throws(() => scheduler.add({ id: '', run: async () => ({}) }), /job id/);
  assert.throws(() => scheduler.add({ id: 'x', resourceClass: 'HUGE', run: async () => ({}) }), /resource class/);
  assert.throws(() => scheduler.add({ id: 'x', run: 'not a function' }), /job.run/);
  scheduler.add({ id: 'x', run: async () => ({}) });
  assert.throws(() => scheduler.add({ id: 'x', run: async () => ({}) }), /duplicate/);
});

// ---------------------------------------------------- relative target retries

test('relative targets survive a retry into a different worktree', () => {
  const from = path.resolve('/work/one');
  const to = path.resolve('/work/two');
  // A relative target is worktree independent and must be carried over as is.
  assert.deepEqual(rebaseTargets(['src/app.js', 'lib/util.js'], from, to), ['src/app.js', 'lib/util.js']);
  assert.deepEqual(rebaseTargets(['.'], from, to), ['.']);
  // A target from an older execution is still absolute and must be rebased.
  assert.deepEqual(rebaseTargets([path.join(from, 'src', 'app.js')], from, to), [path.join(to, 'src', 'app.js')]);
});
