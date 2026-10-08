'use strict';
// Pre-publication gate for the public sentinel-audit repository.
//
// This is a read-only reporter.  It never edits, stages, or publishes anything.
// Its purpose is to make the question "can this tree be published without
// leaking the private Sentinel Cloud implementation or a credential" answerable
// mechanically instead of by memory.
//
// The severity split matters.  BLOCKER means publishing now would leak private
// implementation or a secret.  WARN means the tree is publishable but carries a
// real defect a reader would trip over.  PASS means the property is verified.

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const findings = [];

function add(severity, check, detail, file) {
  findings.push({ severity, check, detail, file: file || null });
}

// Directories that are never published and never scanned for content.
const SKIP_DIRS = new Set(['.git', 'node_modules', 'out', 'coverage', '.cache']);
const TEXT_EXT = new Set([
  '.js', '.cjs', '.mjs', '.json', '.md', '.yml', '.yaml', '.txt', '.sh', '.ps1', '.toml', '.ini', '',
]);

function walk(dir, acc) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, acc);
    else if (entry.isFile()) acc.push(full);
  }
  return acc;
}

function rel(file) { return path.relative(ROOT, file).split(path.sep).join('/'); }

function read(file) {
  try { return fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''); } catch (_) { return null; }
}

const files = walk(ROOT, []);

// ---------------------------------------------------------------------------
// 1. Secrets.  Patterns are deliberately narrow: a rule that fires on ordinary
// prose produces a gate people learn to ignore, which is worse than no gate.
// ---------------------------------------------------------------------------
const SECRET_PATTERNS = [
  { name: 'private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: 'AWS access key id', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'Sentinel Cloud token literal', re: /\bSC_(?:LIVE|TEST)_[A-Za-z0-9]{16,}\b/ },
  { name: 'Bearer literal with value', re: /Authorization["']?\s*[:=]\s*["']Bearer\s+[A-Za-z0-9._-]{16,}/ },
];

for (const file of files) {
  const ext = path.extname(file).toLowerCase();
  if (!TEXT_EXT.has(ext)) continue;
  const text = read(file);
  if (text == null) continue;
  for (const { name, re } of SECRET_PATTERNS) {
    if (re.test(text)) add('BLOCKER', 'secret-scan', `${name} pattern matched`, rel(file));
  }
}

// ---------------------------------------------------------------------------
// 2. Private Sentinel Cloud implementation references.  The public repository
//    must contain a client, never the engine.  A path into the private source
//    tree is the single most likely accidental leak, because it is how the
//    local development wiring works today.
// ---------------------------------------------------------------------------
// Separators are matched as one-or-more so a JSON source file, where a single
// path separator appears as two characters, is detected the same way a JS string
// is.  A gate that misses the central config file is worse than no gate.
const SEP = '[\\\\/]+';
const PRIVATE_TREE = [
  { name: 'sentinel-cloud private source tree', re: new RegExp(`sentinel-cloud${SEP}packages${SEP}worker`, 'i') },
  { name: 'private worker package path', re: new RegExp(`packages${SEP}worker${SEP}(?:core|scan-bridge)`, 'i') },
  { name: 'private scanner module path', re: new RegExp(`core${SEP}scanner${SEP}(?:index|config|ast_inspector)\\.?(?:js|cjs)?`, 'i') },
  { name: 'direct engine require() of cloud source', re: /loadEngine\(enginePath\)|require\([^)]*sentinel-cloud/i },
];

for (const file of files) {
  const ext = path.extname(file).toLowerCase();
  if (!TEXT_EXT.has(ext)) continue;
  const text = read(file);
  if (text == null) continue;
  for (const { name, re } of PRIVATE_TREE) {
    if (re.test(text)) add('BLOCKER', 'private-implementation', `${name} referenced`, rel(file));
  }
}

// ---------------------------------------------------------------------------
// 3. Host-specific absolute paths.  These make a published tree unusable for a
//    reader, and they disclose the maintainer's directory layout.
// ---------------------------------------------------------------------------
const HOST_PATHS = [
  { name: 'USERPROFILE absolute path', re: new RegExp(`%USERPROFILE%${SEP}?(?:sentinel-cloud|AppData)`, 'i') },
  { name: 'LOCALAPPDATA tool path', re: new RegExp(`%LOCALAPPDATA%${SEP}opencode${SEP}tools`, 'i') },
  { name: 'bare home-relative cloud path', re: new RegExp(`[A-Za-z]:${SEP}Users${SEP}[^\\\\\\s"']*sentinel-cloud`, 'i') },
];

for (const file of files) {
  const ext = path.extname(file).toLowerCase();
  if (!TEXT_EXT.has(ext)) continue;
  const text = read(file);
  if (text == null) continue;
  for (const { name, re } of HOST_PATHS) {
    if (re.test(text)) add('WARN', 'host-specific-path', `${name} is not portable`, rel(file));
  }
}

// ---------------------------------------------------------------------------
// 4. Semgrep registry rules must not be vendored.  The Semgrep Rules License
//    governs registry content separately from the CLI, and a published
//    repository must not redistribute it.  Our own rules are idspaced
//    `sentinel.*`; anything else came from the registry.
// ---------------------------------------------------------------------------
const rulesDir = path.join(ROOT, 'rules');
if (fs.existsSync(rulesDir)) {
  const ruleFiles = [];
  const collect = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) collect(full);
      else if (/\.(?:yml|yaml)$/i.test(e.name)) ruleFiles.push(full);
    }
  };
  collect(rulesDir);
  if (!ruleFiles.length) add('BLOCKER', 'rules-license', 'no vendored ruleset found; the deterministic ruleset is missing', 'rules/');
  for (const file of ruleFiles) {
    const text = read(file) || '';
    const ids = [...text.matchAll(/^\s*-\s*id:\s*(\S+)/gm)].map((m) => m[1]);
    if (!ids.length) { add('WARN', 'rules-license', 'ruleset declares no rule ids', rel(file)); continue; }
    const foreign = ids.filter((id) => !id.startsWith('sentinel.'));
    if (foreign.length) add('BLOCKER', 'rules-license', `non-sentinel rule ids present: ${foreign.join(', ')}`, rel(file));
    if (/\bp\/[a-z0-9-]+\//i.test(text)) add('BLOCKER', 'rules-license', 'remote registry ruleset reference in vendored config', rel(file));
  }
} else {
  add('WARN', 'rules-license', 'no rules/ directory', 'rules/');
}

// ---------------------------------------------------------------------------
// 5. Publishability of the manifest itself.
// ---------------------------------------------------------------------------
const pkg = JSON.parse(read(path.join(ROOT, 'package.json')) || '{}');
if (pkg.private === true) add('BLOCKER', 'package-manifest', '"private": true forbids publication', 'package.json');
if (!pkg.license || pkg.license === 'UNLICENSED') add('BLOCKER', 'package-manifest', `license is ${pkg.license || 'missing'}; a public repo without a license is all-rights-reserved by default`, 'package.json');
if (!pkg.bin || !Object.keys(pkg.bin).length) add('WARN', 'package-manifest', 'no bin entry; the tool is not installable as a command', 'package.json');
if (!pkg.files) add('WARN', 'package-manifest', 'no "files" allowlist; npm would publish out/ and test fixtures if they were not ignored', 'package.json');
if (pkg.dependencies && Object.keys(pkg.dependencies).length) {
  add('PASS', 'package-manifest', `${Object.keys(pkg.dependencies).length} runtime dependencies to license-review`, 'package.json');
} else {
  add('PASS', 'package-manifest', 'zero runtime dependencies', 'package.json');
}

// ---------------------------------------------------------------------------
// 6. Required public-repository documents.
// ---------------------------------------------------------------------------
const REQUIRED_DOCS = [
  ['LICENSE', 'no LICENSE file: the tree is not open source without one'],
  ['SECURITY.md', 'no SECURITY.md: no private disclosure channel for a public tool'],
  ['CONTRIBUTING.md', 'no CONTRIBUTING.md'],
  ['README.md', 'no README.md'],
];
for (const [name, message] of REQUIRED_DOCS) {
  if (!fs.existsSync(path.join(ROOT, name))) add('WARN', 'public-docs', message, name);
}

// ---------------------------------------------------------------------------
// 7. Local evidence must not be published.  A raw Cloud artifact or an
//    acceptance run can contain third-party source and engine output.
// ---------------------------------------------------------------------------
const EVIDENCE_NAMES = /^(?:raw\.json|expediente\.json|manifest\.json|.*\.log)$/i;
for (const file of files) {
  const r = rel(file);
  if (/^(?:out|test\/fixtures)\//.test(r) && EVIDENCE_NAMES.test(path.basename(file))) {
    add('BLOCKER', 'evidence-leak', 'raw execution evidence would be published', r);
  }
}
for (const name of ['.env', '.env.local', '.npmrc']) {
  if (fs.existsSync(path.join(ROOT, name))) add('BLOCKER', 'evidence-leak', `${name} present`, name);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const ORDER = { BLOCKER: 0, WARN: 1, PASS: 2 };
findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || a.check.localeCompare(b.check));

const counts = { BLOCKER: 0, WARN: 0, PASS: 0 };
for (const f of findings) counts[f.severity] += 1;

const asJson = process.argv.includes('--json');
if (asJson) {
  process.stdout.write(JSON.stringify({ root: ROOT, counts, findings }, null, 2) + '\n');
} else {
  process.stdout.write('public-release-audit\n');
  process.stdout.write(`root: ${ROOT}\n\n`);
  for (const f of findings) {
    const where = f.file ? ` (${f.file})` : '';
    process.stdout.write(`${f.severity.padEnd(7)} ${f.check.padEnd(24)} ${f.detail}${where}\n`);
  }
  process.stdout.write(`\nBLOCKER ${counts.BLOCKER}  WARN ${counts.WARN}  PASS ${counts.PASS}\n`);
  process.stdout.write(counts.BLOCKER
    ? '\nNOT PUBLISHABLE: resolve every BLOCKER before creating a public repository.\n'
    : counts.WARN
      ? '\nPublishable with warnings: a public reader will trip over the WARN items.\n'
      : '\nPublishable: no private implementation, secret, or evidence leak detected.\n');
}

process.exit(counts.BLOCKER ? 1 : 0);
