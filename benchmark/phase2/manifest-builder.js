'use strict';

/**
 * Phase 2 — Target Manifest Builder
 *
 * Scans local real-world OSS packages, extracts metadata,
 * computes deterministic SHA-256 target hashes, and writes PHASE2_MANIFEST.json.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { PATHS, CANONICAL_FREEZE, MAX_FILES_PER_PACKAGE } = require('./config');

function collectCodeFiles(dir, maxFiles = MAX_FILES_PER_PACKAGE) {
  const files = [];
  function walk(current) {
    if (files.length >= maxFiles) return;
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (files.length >= maxFiles) break;
      const fullPath = path.join(current, ent.name);
      if (ent.isDirectory()) {
        if (ent.name === 'node_modules' || ent.name === '.git') continue;
        walk(fullPath);
      } else if (ent.isFile()) {
        if (ent.name === 'package-lock.json') continue;
        // Collect JS, TS, JSON, YAML, etc.
        const ext = path.extname(ent.name).toLowerCase();
        if (['.js', '.mjs', '.cjs', '.ts', '.json', '.yaml', '.yml', '.sh'].includes(ext) || ent.name === 'package.json') {
          files.push(fullPath);
        }
      }
    }
  }
  walk(dir);
  return files.sort();
}

function computeTargetHash(baseDir, files) {
  const hash = crypto.createHash('sha256');
  for (const fp of files) {
    const rel = path.relative(baseDir, fp).replace(/\\/g, '/');
    hash.update(rel);
    try {
      const buf = fs.readFileSync(fp);
      hash.update(buf);
    } catch (e) {
      hash.update(e.message);
    }
  }
  return hash.digest('hex');
}

function buildManifest(options = {}) {
  const targets = [];
  const dirs = [
    { subset: 'curated-benign', root: PATHS.benignDir },
    { subset: 'blind-benign', root: PATHS.blindBenignDir }
  ];

  console.log('Discovering Phase 2 targets...');

  for (const { subset, root } of dirs) {
    if (!fs.existsSync(root)) {
      console.warn(`Directory not found: ${root}`);
      continue;
    }
    const entries = fs.readdirSync(root, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      const pkgDir = path.join(root, ent.name, 'package');
      const targetDir = fs.existsSync(pkgDir) ? pkgDir : path.join(root, ent.name);
      
      const parts = ent.name.split('@');
      let version = 'unknown';
      let name = ent.name;
      if (parts.length >= 2) {
        version = parts.pop();
        name = parts.join('@');
      }

      // Check package.json if present
      const pkgJsonPath = path.join(targetDir, 'package.json');
      let pkgInfo = { name, version };
      if (fs.existsSync(pkgJsonPath)) {
        try {
          const parsed = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
          if (parsed.name) pkgInfo.name = parsed.name;
          if (parsed.version) pkgInfo.version = parsed.version;
        } catch {}
      }

      const files = collectCodeFiles(targetDir, MAX_FILES_PER_PACKAGE);
      if (files.length === 0) continue;

      let byteCount = 0;
      for (const fp of files) {
        try { byteCount += fs.statSync(fp).size; } catch {}
      }

      const targetHash = computeTargetHash(targetDir, files);

      targets.push({
        targetId: `${pkgInfo.name}@${pkgInfo.version}`,
        packageName: pkgInfo.name,
        version: pkgInfo.version,
        subset,
        directory: targetDir,
        fileCount: files.length,
        byteCount,
        targetHash,
        groundTruth: 'BENIGN',
        acquisition: 'offline-npm-pack',
        files: files.map(f => path.relative(targetDir, f).replace(/\\/g, '/'))
      });
    }
  }

  targets.sort((a, b) => a.targetId.localeCompare(b.targetId));

  const manifest = {
    schemaVersion: '2.0.0',
    campaign: 'PHASE2_REAL_WORLD_BENIGN_OSS',
    generatedAt: new Date().toISOString(),
    canonicalFreeze: CANONICAL_FREEZE,
    totalTargets: targets.length,
    curatedBenignCount: targets.filter(t => t.subset === 'curated-benign').length,
    blindBenignCount: targets.filter(t => t.subset === 'blind-benign').length,
    targets
  };

  fs.writeFileSync(PATHS.manifestFile, JSON.stringify(manifest, null, 2), 'utf8');
  console.log(`Manifest built successfully with ${targets.length} targets: ${PATHS.manifestFile}`);
  return manifest;
}

if (require.main === module) {
  buildManifest();
}

module.exports = { buildManifest, collectCodeFiles, computeTargetHash };
