'use strict';
/**
 * Path identity for routing targets.
 *
 * The persisted contract for a routing target is a repository-relative path.
 * Absolute paths are never the logical identity of a target: they embed the
 * execution directory, they are not portable between hosts, and they are
 * meaningless once the disposable worktree has been cleaned up.  A retry
 * rebuilds its worktree somewhere else, so an absolute target left in the
 * expediente would point at a directory that no longer exists.
 *
 * Everything that persists a target uses `relTarget`; everything that touches
 * the filesystem resolves with `abs` against the root of the *current*
 * execution.
 */
const fs = require('fs');
const path = require('path');

// Resolve a target against a root and refuse anything that escapes it.
// Returns null when the result would leave the audited repository.
function abs(root, candidate) {
  if (!candidate || typeof candidate !== 'string') return null;
  const base = path.resolve(root);
  const output = path.resolve(base, candidate.replace(/\\/g, '/'));
  const relative = path.relative(base, output);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return null;
  return output;
}

// Express a path as a repository-relative identity, using forward slashes so the
// value is identical on every host.  The repository root itself is '.', which is
// the identity a repo-scoped target must carry.
function relTarget(root, candidate) {
  const absolute = path.resolve(candidate);
  const relative = path.relative(path.resolve(root), absolute);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return null;
  return relative === '' ? '.' : relative.split(path.sep).join('/');
}

// Containment check performed on the *real* path, so a symlink or a Windows
// junction inside the repository cannot be used to reach a target outside it.
function realContained(root, absolute) {
  let real;
  try { real = fs.realpathSync(absolute); } catch (error) { return { ok: false, reason: `unresolvable: ${error.code || error.message}` }; }
  const realRoot = (() => { try { return fs.realpathSync(path.resolve(root)); } catch (error) { return path.resolve(root); } })();
  const relative = path.relative(realRoot, real);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    return { ok: false, reason: 'resolves outside the audited repository' };
  }
  return { ok: true, real };
}

module.exports = { abs, relTarget, realContained };
