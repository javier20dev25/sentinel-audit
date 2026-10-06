'use strict';
/** Managed, disposable checkout creation.  Target repositories are never edited. */
const fs = require('fs');
const path = require('path');
const { run } = require('../lib/core');
const { contained, writeJson } = require('./artifacts');

function git(repo, args, timeoutMs = 120000) {
  const root = path.resolve(repo);
  return run('git', ['-c', `safe.directory=${root}`, '-C', root, ...args], { timeoutMs });
}

function gitOutput(repo, args, timeoutMs) {
  const result = git(repo, args, timeoutMs);
  return result.ok ? result.stdout.trim() : null;
}

function createManagedCheckout(sourceRepo, commit, executionDir, opts = {}) {
  const source = path.resolve(sourceRepo);
  const destination = contained(executionDir, 'worktree');
  if (!commit) throw new Error('a pinned commit is required for a managed checkout');
  if (fs.existsSync(destination)) throw new Error('managed worktree already exists for this execution');
  const clone = run('git', [
    '-c', `safe.directory=${source}`,
    '-c', 'core.hooksPath=',
    // Windows caps paths at 260 characters unless long paths are enabled, and
    // an execution directory plus a nested worktree/.git/hooks path exceeds it
    // easily.  Without this the clone fails with "Filename too long" and takes
    // the whole run with it.
    '-c', 'core.longpaths=true',
    'clone', '--no-checkout', '--no-local', '--config', 'core.autocrlf=false', '--config', 'core.longpaths=true', '--', source, destination,
  ], { timeoutMs: opts.timeoutMs || 180000 });
  if (!clone.ok) throw new Error(`managed clone failed: ${clone.error || clone.stderr || clone.status}`);
  const checkout = git(destination, ['-c', 'core.hooksPath=', '-c', 'core.autocrlf=false', '-c', 'core.longpaths=true', 'checkout', '--detach', '--no-recurse-submodules', commit], opts.timeoutMs || 180000);
  if (!checkout.ok) throw new Error(`managed checkout failed: ${checkout.error || checkout.stderr || checkout.status}`);
  const actualCommit = gitOutput(destination, ['rev-parse', 'HEAD']);
  const tree = gitOutput(destination, ['rev-parse', 'HEAD^{tree}']);
  const clean = gitOutput(destination, ['status', '--porcelain', '--untracked-files=all']) === '';
  if (actualCommit !== commit || !clean) throw new Error(`managed checkout identity mismatch: expected ${commit}, got ${actualCommit || 'unknown'}, clean=${clean}`);
  const metadata = {
    mode: 'managed-clone', sourceRepo: source, path: destination, requestedCommit: commit,
    commit: actualCommit, tree, workingTreeClean: clean,
    remoteUrl: gitOutput(destination, ['config', '--get', 'remote.origin.url']),
    cloneStatus: clone.status, checkoutStatus: checkout.status,
  };
  writeJson(contained(executionDir, 'state', 'workspace.json'), metadata);
  return metadata;
}

function rebaseTargets(targets, fromRoot, toRoot) {
  if (!Array.isArray(targets)) return targets;
  const from = path.resolve(fromRoot);
  const to = path.resolve(toRoot);
  return targets.map((target) => {
    if (typeof target !== 'string' || target === '') return target;
    // A relative target is already the persisted contract and is independent of
    // the worktree it was recorded in, so it is carried over untouched.
    // path.resolve() on it would anchor it to the process cwd and produce a path
    // that belongs to no execution at all.
    if (!path.isAbsolute(target)) return target.split(path.sep).join('/');
    const absolute = path.resolve(target);
    const relative = path.relative(from, absolute);
    // Only rebase paths that really lived under the previous worktree.  Anything
    // else is returned untouched so the adapter's own containment check still
    // rejects it instead of this helper silently widening the blast radius.
    if (relative && !relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative)) {
      return path.join(to, relative);
    }
    return absolute;
  });
}

function cleanupManagedCheckout(executionDir, { keepWorktree = false } = {}) {
  const target = contained(executionDir, 'worktree');
  const attempted = [target];
  if (keepWorktree) return { cleanupStatus: 'PARTIAL', cleanupErrors: [], pathsAttempted: attempted, pathsRemoved: [], retained: [target], note: 'worktree retained by --keep-worktree' };
  if (!fs.existsSync(target)) return { cleanupStatus: 'CLEAN', cleanupErrors: [], pathsAttempted: attempted, pathsRemoved: [], retained: [] };
  const errors = [];
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) throw new Error('refused to remove symbolic-link worktree');
      fs.rmSync(target, { recursive: true, force: false, maxRetries: 1, retryDelay: 120 });
      if (!fs.existsSync(target)) break;
    } catch (error) {
      errors.push(`attempt ${attempt + 1}: ${error.message}`);
    }
  }
  const removed = !fs.existsSync(target);
  return {
    cleanupStatus: removed ? 'CLEAN' : 'BLOCKED',
    cleanupErrors: removed ? [] : errors,
    pathsAttempted: attempted,
    pathsRemoved: removed ? [target] : [],
    retained: removed ? [] : [target],
  };
}

module.exports = { git, gitOutput, createManagedCheckout, cleanupManagedCheckout, rebaseTargets };
