'use strict';

/**
 * Phase 3 — Manifest Builder
 *
 * Walks zip_malware/<packagename>/<version>/<pkg-version.tgz>
 * Selects ONE version per package (latest by semver, fallback to first alphabetically).
 * Ground truth for all entries: MALICIOUS
 *
 * Usage: node manifest-builder.js [--limit N]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { PATHS, CANONICAL_FREEZE } = require('./config');

function parseSemver(v) {
  // Returns [major, minor, patch, pre] for loose comparison
  const clean = v.replace(/^[^0-9]*/, '');
  const [core, pre] = clean.split('-');
  const parts = (core || '0').split('.').map(n => parseInt(n, 10) || 0);
  while (parts.length < 3) parts.push(0);
  return { major: parts[0], minor: parts[1], patch: parts[2], pre: pre || '' };
}

function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (pa.major !== pb.major) return pb.major - pa.major;
  if (pa.minor !== pb.minor) return pb.minor - pa.minor;
  if (pa.patch !== pb.patch) return pb.patch - pa.patch;
  // pre-release: no pre > has pre
  if (!pa.pre && pb.pre) return -1;
  if (pa.pre && !pb.pre) return 1;
  return pa.pre < pb.pre ? -1 : 1;
}

function findTgzForVersion(versionDir) {
  try {
    return fs.readdirSync(versionDir)
      .filter(f => f.endsWith('.tgz'))
      .map(f => path.join(versionDir, f))[0] || null;
  } catch {
    return null;
  }
}

function hashFileSha256(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch {
    return null;
  }
}

function statSafe(p) {
  try { return fs.statSync(p); } catch { return null; }
}

async function buildManifest(options = {}) {
  const malwareDir = PATHS.malwareDir;
  const manifestFile = PATHS.manifestFile;
  const limit = options.limit || Infinity;

  console.log('=======================================================');
  console.log('SENTINEL PHASE 3 — MANIFEST BUILDER');
  console.log(`Scanning: ${malwareDir}`);
  console.log('=======================================================\n');

  if (!fs.existsSync(malwareDir)) {
    throw new Error(`Malware directory not found: ${malwareDir}`);
  }

  const packageNames = fs.readdirSync(malwareDir)
    .filter(name => {
      const p = path.join(malwareDir, name);
      return statSafe(p)?.isDirectory();
    })
    .sort();

  console.log(`Found ${packageNames.length} package name directories.`);

  const targets = [];
  let skipped = 0;
  let processed = 0;

  for (const pkgName of packageNames) {
    if (targets.length >= limit) break;

    const pkgDir = path.join(malwareDir, pkgName);
    let versionDirs;
    try {
      versionDirs = fs.readdirSync(pkgDir)
        .filter(v => statSafe(path.join(pkgDir, v))?.isDirectory());
    } catch {
      skipped++;
      continue;
    }

    if (versionDirs.length === 0) {
      skipped++;
      continue;
    }

    // Pick latest version by semver
    versionDirs.sort(compareSemver);
    const selectedVersion = versionDirs[0];
    const versionDir = path.join(pkgDir, selectedVersion);
    const tgzPath = findTgzForVersion(versionDir);

    if (!tgzPath || !fs.existsSync(tgzPath)) {
      skipped++;
      continue;
    }

    const st = statSafe(tgzPath);
    const tgzHash = hashFileSha256(tgzPath);

    const targetId = `${pkgName}@${selectedVersion}`;

    targets.push({
      targetId,
      packageName: pkgName,
      version: selectedVersion,
      tgzPath: tgzPath.replace(/\\/g, '/'),
      tgzSizeBytes: st?.size || 0,
      tgzSha256: tgzHash,
      groundTruth: 'MALICIOUS',
      availableVersions: versionDirs.length,
      allVersions: versionDirs
    });

    processed++;
    if (processed % 500 === 0) {
      console.log(`  Processed ${processed} packages...`);
    }
  }

  const manifest = {
    schemaVersion: '3.0',
    generatedAt: new Date().toISOString(),
    freeze: CANONICAL_FREEZE,
    corpus: {
      source: 'NPMStudy zip_malware',
      malwareDir: PATHS.malwareDir,
      groundTruth: 'ALL_MALICIOUS',
      selectionStrategy: 'latest_semver_per_package'
    },
    summary: {
      totalPackageDirectories: packageNames.length,
      targetsSelected: targets.length,
      skipped,
      limitApplied: limit === Infinity ? null : limit
    },
    targets
  };

  fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));
  console.log(`\nManifest written: ${manifestFile}`);
  console.log(`Targets: ${targets.length} | Skipped: ${skipped}`);
  return manifest;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const limitIdx = args.indexOf('--limit');
  const limit = limitIdx !== -1 ? parseInt(args[limitIdx + 1], 10) : Infinity;
  buildManifest({ limit }).catch(err => {
    console.error('Manifest build failed:', err);
    process.exit(1);
  });
}

module.exports = { buildManifest };
