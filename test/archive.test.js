'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const { packRepository, walkFiles, ARCHIVE_MAX_BYTES } = require('../workflow/archive');

function tempRepo() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-archive-'));
}

function write(root, rel, content) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

/** Minimal ustar reader: returns ordered entries with name, size and body. */
function readTar(buffer) {
  const entries = [];
  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = header.toString('utf8', 0, 100).replace(/\0.*$/, '');
    const prefix = header.toString('utf8', 345, 345 + 155).replace(/\0.*$/, '');
    const size = parseInt(header.toString('ascii', 124, 136).replace(/\0.*$/, '').trim() || '0', 8);
    const mtime = parseInt(header.toString('ascii', 136, 148).replace(/\0.*$/, '').trim() || '0', 8);
    const start = offset + 512;
    entries.push({ name: prefix ? `${prefix}/${name}` : name, size, mtime, body: buffer.subarray(start, start + size) });
    offset = start + Math.ceil(size / 512) * 512;
  }
  return entries;
}

test('packRepository output is byte-identical across runs', () => {
  const root = tempRepo();
  write(root, 'src/app.js', 'console.log("a");\n');
  write(root, 'README.md', '# repo\n');
  write(root, 'src/nested/deep/module.js', 'module.exports = 1;\n');
  const first = packRepository(root, {});
  const second = packRepository(root, {});
  assert.equal(first.sha256, second.sha256);
  assert.deepEqual(first.bytes, second.bytes);
});

test('gzip stream round-trips to a ustar stream with zeroed metadata', () => {
  const root = tempRepo();
  write(root, 'a.txt', 'alpha');
  write(root, 'dir/b.txt', 'beta');
  const { bytes, included } = packRepository(root, {});
  const raw = zlib.gunzipSync(bytes);
  const entries = readTar(raw);
  assert.deepEqual(entries.map((entry) => entry.name), included);
  assert.deepEqual(included, ['a.txt', 'dir/b.txt']);
  assert.ok(entries.every((entry) => entry.mtime === 0), 'mtime must be zeroed for determinism');
  assert.equal(entries[0].body.toString('utf8'), 'alpha');
  // Two zero blocks terminate the stream.
  assert.ok(raw.subarray(-1024).every((byte) => byte === 0));
});

test('entries are sorted by path regardless of input order', () => {
  const root = tempRepo();
  write(root, 'z.txt', 'z');
  write(root, 'a.txt', 'a');
  write(root, 'm/m.txt', 'm');
  const { included } = packRepository(root, { files: ['z.txt', 'm/m.txt', 'a.txt'] });
  assert.deepEqual(included, ['a.txt', 'm/m.txt', 'z.txt']);
});

test('walkFiles skips .git and node_modules, never follows symlinks', () => {
  const root = tempRepo();
  write(root, 'app.js', 'x');
  write(root, '.git/config', 'core');
  write(root, 'node_modules/dep/index.js', 'y');
  const files = walkFiles(root);
  assert.deepEqual(files, ['app.js']);
});

test('symlinks are skipped and reported, never packed', (t) => {
  const root = tempRepo();
  write(root, 'real.txt', 'real');
  const link = path.join(root, 'link.txt');
  try {
    fs.symlinkSync(path.join(root, 'real.txt'), link, 'file');
  } catch (_) {
    t.skip('host does not allow creating symlinks without elevation');
    return;
  }
  const packed = packRepository(root, { files: ['real.txt', 'link.txt'] });
  assert.deepEqual(packed.included, ['real.txt']);
  assert.deepEqual(packed.skippedSymlinks, ['link.txt']);
});

test('files over maxFileBytes are skipped and reported', () => {
  const root = tempRepo();
  write(root, 'small.txt', 'ab');
  write(root, 'big.txt', 'abcdefghij');
  const packed = packRepository(root, { files: ['small.txt', 'big.txt'], maxFileBytes: 4 });
  assert.deepEqual(packed.included, ['small.txt']);
  assert.deepEqual(packed.skippedOversized, ['big.txt']);
});

test('paths that try to escape the repository are dropped, not packed', () => {
  const root = tempRepo();
  write(root, 'ok.txt', 'ok');
  const packed = packRepository(root, { files: ['ok.txt', '../outside.txt', '..\\..\\evil.txt', '/etc/passwd', 'C:\\Windows\\win.ini'] });
  assert.deepEqual(packed.included, ['ok.txt']);
  assert.equal(packed.fileCount, 1);
});

test('a cap breach throws instead of truncating the archive', () => {
  const root = tempRepo();
  write(root, 'a.txt', 'aaaa');
  write(root, 'b.txt', 'bbbb');
  assert.throws(() => packRepository(root, { files: ['a.txt', 'b.txt'], maxFiles: 1 }), /exceeds 1 files/);
  assert.throws(() => packRepository(root, { files: ['a.txt', 'b.txt'], maxTotalBytes: 1 }), /uncompressed bytes/);
  assert.throws(() => packRepository(root, { files: ['a.txt'], maxArchiveBytes: 1 }), /over the 1 byte cap/);
});

test('default archive cap matches the server contract', () => {
  assert.equal(ARCHIVE_MAX_BYTES, 26214400);
});

test('sha256 identifies the exact bytes written', () => {
  const root = tempRepo();
  write(root, 'only.txt', 'payload');
  const packed = packRepository(root, {});
  assert.equal(packed.sha256, crypto.createHash('sha256').update(packed.bytes).digest('hex'));
  assert.equal(packed.archiveBytes, packed.bytes.length);
});
