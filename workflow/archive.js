'use strict';
/**
 * Deterministic, dependency-free repository packer.
 *
 * The hosted scan uploads the caller's source tree, so this file is the one
 * place in the runner allowed to turn a repository into bytes on the wire.  It
 * has three properties that are not negotiable:
 *
 *   1. No third-party dependency and no `tar`/`gzip` child process.  Shelling
 *      out would hand the packing of the user's source to whatever `tar` exists
 *      on PATH, and `execSync("tar")` on Windows is a coin flip.
 *   2. Deterministic output.  Entries are sorted by path, timestamps are zeroed
 *      and the gzip header is written by hand, so the same tree yields the same
 *      bytes and the same sha256 on every host.  A recorded archive hash is only
 *      evidence if it is reproducible.
 *   3. Fail-closed on anything surprising.  Symlinks are never followed (they
 *      can escape the repository), the caller receives an explicit list of what
 *      was skipped, and an archive over the server cap raises instead of being
 *      silently truncated into a scan of half the repository.
 *
 * The archive is a POSIX ustar stream, which is all the server extractor reads.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const BLOCK = 512;

/** Mirrors the server's archive cap (sentinel-cloud-client REPOSITORY_SCAN_MAX_ARCHIVE_BYTES). */
const ARCHIVE_MAX_BYTES = 26214400;
const MAX_FILES_DEFAULT = 50000;
/** Upper bound on the uncompressed stream, so a pathological tree cannot OOM the runner. */
const MAX_TOTAL_BYTES_DEFAULT = 268435456;

// ---------------------------------------------------------------- gzip
// A hand-written gzip wrapper (RFC 1952) so no ambient zlib setting can leak
// into the header.  Node's zlib.gzip() writes an OS byte and XFL that vary by
// build; an explicit header makes the archive byte-identical across hosts.
const CRC_TABLE = new Int32Array(256);
for (let n = 0; n < 256; n += 1) {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC_TABLE[n] = c;
}

function crc32(buffer) {
  let crc = -1;
  for (let i = 0; i < buffer.length; i += 1) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xff];
  return (crc ^ -1) >>> 0;
}

function gzipDeterministic(raw) {
  const deflated = zlib.deflateRawSync(raw, { level: 9 });
  const header = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
  const footer = Buffer.alloc(8);
  footer.writeUInt32LE(crc32(raw) >>> 0, 0);
  footer.writeUInt32LE(raw.length >>> 0, 4);
  return Buffer.concat([header, deflated, footer]);
}

// ---------------------------------------------------------------- tar
function octal(value, width) {
  const text = Math.max(0, Math.floor(value)).toString(8);
  return `${text.padStart(width - 1, '0')}\0`;
}

/** Writes a UTF-8 string into a fixed-width field, never exceeding it. */
function put(buffer, value, offset, length) {
  const bytes = Buffer.from(String(value == null ? '' : value), 'utf8');
  bytes.copy(buffer, offset, 0, Math.min(bytes.length, length));
}

/**
 * Ustar splits paths longer than 100 bytes into a 155-byte prefix plus the
 * final 100-byte name.  The split point is chosen from the end so the result is
 * stable for a given path.
 */
function splitName(name) {
  if (Buffer.byteLength(name, 'utf8') <= 100) return { nameField: name, prefix: '' };
  let index = name.lastIndexOf('/');
  while (index > 0) {
    const prefix = name.slice(0, index);
    const rest = name.slice(index + 1);
    if (Buffer.byteLength(prefix, 'utf8') <= 155 && Buffer.byteLength(rest, 'utf8') <= 100) {
      return { nameField: rest, prefix };
    }
    index = name.lastIndexOf('/', index - 1);
  }
  throw new Error(`archive path is too long for POSIX ustar: ${name}`);
}

function tarHeader({ name, size, mode = 0o644, mtime = 0, type = '0' }) {
  const header = Buffer.alloc(BLOCK);
  const { nameField, prefix } = splitName(name);
  put(header, nameField, 0, 100);
  put(header, octal(mode, 8), 100, 8);
  put(header, octal(0, 8), 108, 8); // uid
  put(header, octal(0, 8), 116, 8); // gid
  put(header, octal(size, 12), 124, 12);
  put(header, octal(mtime, 12), 136, 12);
  header.write('        ', 148, 8, 'ascii'); // checksum field starts blank
  header.write(type, 156, 1, 'ascii');
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  put(header, 'root', 265, 32); // uname
  put(header, 'root', 297, 32); // gname
  put(header, octal(0, 8), 329, 8); // devmajor
  put(header, octal(0, 8), 337, 8); // devminor
  put(header, prefix, 345, 155);
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
  return header;
}

function padToBlock(buffer) {
  const remainder = buffer.length % BLOCK;
  if (remainder === 0) return buffer;
  return Buffer.concat([buffer, Buffer.alloc(BLOCK - remainder)]);
}

// ---------------------------------------------------------------- packing
const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build']);

/** Normalizes a caller path to a repo-relative, forward-slash identity or null. */
function safeRelative(rel) {
  if (typeof rel !== 'string' || rel.trim() === '') return null;
  const normalized = rel.replace(/\\/g, '/').replace(/^\.\//, '');
  if (normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized)) return null;
  const parts = normalized.split('/');
  if (parts.some((part) => part === '..')) return null;
  return parts.filter((part) => part !== '.').join('/');
}

/** Filesystem fallback when the caller has no git-tracked list. Never follows symlinks. */
function walkFiles(root) {
  const out = [];
  const stack = ['.'];
  while (stack.length) {
    const rel = stack.pop();
    const full = path.join(root, rel);
    let entries;
    try { entries = fs.readdirSync(full, { withFileTypes: true }); } catch (_) { continue; }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const childRel = rel === '.' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) { if (!SKIP_DIRS.has(entry.name)) stack.push(childRel); continue; }
      if (entry.isFile()) out.push(childRel);
    }
  }
  return out.sort();
}

/**
 * Builds the archive for `root`.  `files` is authoritative when supplied (the
 * runner passes the git-tracked list); otherwise the tree is walked.
 *
 * Returns { bytes, sha256, fileCount, archiveBytes, uncompressedBytes,
 *           skippedSymlinks, skippedOversized, skippedNonFile, included }.
 * Throws on a cap breach, an escaping path, or a path ustar cannot represent.
 */
function packRepository(root, opts = {}) {
  const base = path.resolve(root);
  const maxFiles = Number.isInteger(opts.maxFiles) && opts.maxFiles > 0 ? opts.maxFiles : MAX_FILES_DEFAULT;
  const maxFileBytes = Number.isInteger(opts.maxFileBytes) && opts.maxFileBytes > 0 ? opts.maxFileBytes : Infinity;
  const maxTotalBytes = Number.isInteger(opts.maxTotalBytes) && opts.maxTotalBytes > 0 ? opts.maxTotalBytes : MAX_TOTAL_BYTES_DEFAULT;
  const maxArchiveBytes = Number.isInteger(opts.maxArchiveBytes) && opts.maxArchiveBytes > 0 ? opts.maxArchiveBytes : ARCHIVE_MAX_BYTES;

  const requested = Array.isArray(opts.files) ? opts.files : walkFiles(base);
  const seen = new Set();
  const candidates = [];
  for (const rel of requested) {
    const normalized = safeRelative(rel);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    candidates.push(normalized);
  }
  candidates.sort();

  const skippedSymlinks = [];
  const skippedOversized = [];
  const skippedNonFile = [];
  const included = [];
  const chunks = [];
  let totalBytes = 0;

  for (const rel of candidates) {
    const full = path.resolve(base, rel);
    // The containment check runs on the resolved path; a crafted `rel` cannot
    // reach outside the repository even before lstat.
    if (full !== base && !full.startsWith(base + path.sep)) throw new Error(`archive entry escapes the repository: ${rel}`);
    let stat;
    try { stat = fs.lstatSync(full); } catch (_) { skippedNonFile.push(rel); continue; }
    if (stat.isSymbolicLink()) { skippedSymlinks.push(rel); continue; }
    if (!stat.isFile()) { skippedNonFile.push(rel); continue; }
    if (stat.size > maxFileBytes) { skippedOversized.push(rel); continue; }
    if (included.length + 1 > maxFiles) throw new Error(`repository archive exceeds ${maxFiles} files`);
    if (totalBytes + stat.size > maxTotalBytes) throw new Error(`repository archive exceeds ${maxTotalBytes} uncompressed bytes`);
    const content = fs.readFileSync(full);
    chunks.push(tarHeader({ name: rel, size: content.length }));
    chunks.push(padToBlock(content));
    totalBytes += content.length;
    included.push(rel);
  }

  if (chunks.length === 0) chunks.push(Buffer.alloc(0));
  chunks.push(Buffer.alloc(BLOCK * 2)); // two zero blocks terminate a tar stream
  const raw = Buffer.concat(chunks);
  const bytes = gzipDeterministic(raw);

  if (bytes.length > maxArchiveBytes) {
    throw new Error(`repository archive is ${bytes.length} bytes, over the ${maxArchiveBytes} byte cap`);
  }

  return {
    bytes,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    fileCount: included.length,
    archiveBytes: bytes.length,
    uncompressedBytes: raw.length,
    skippedSymlinks,
    skippedOversized,
    skippedNonFile,
    included,
  };
}

module.exports = {
  packRepository,
  walkFiles,
  ARCHIVE_MAX_BYTES,
  MAX_FILES_DEFAULT,
  MAX_TOTAL_BYTES_DEFAULT,
};
