/**
 * Phase 4 — Manifest Builder
 * Reads expectedresults-1.2.csv, finds each BenchmarkTest*.java file,
 * computes SHA-256, and writes PHASE4_MANIFEST.json.
 */
'use strict';

const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { TESTCODE_DIR, EXPECTED_CSV, PHASE4_DIR, ENVIRONMENT } = require('./config');

const MANIFEST_PATH = path.join(PHASE4_DIR, 'PHASE4_MANIFEST.json');

function sha256File(fp) {
  return crypto.createHash('sha256').update(fs.readFileSync(fp)).digest('hex');
}

function buildManifest() {
  const raw = fs.readFileSync(EXPECTED_CSV, 'utf8');
  const lines = raw.split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith('#'));

  const entries = [];
  const missing = [];

  for (const line of lines) {
    const parts = line.split(',');
    if (parts.length < 3) continue;

    const testName     = parts[0].trim();
    const category     = parts[1].trim();
    const vulnerable   = parts[2].trim().toLowerCase() === 'true';
    const cwe          = parts[3] ? parseInt(parts[3].trim(), 10) : null;

    const javaFile = path.join(TESTCODE_DIR, testName + '.java');
    if (!fs.existsSync(javaFile)) {
      missing.push(testName);
      continue;
    }

    entries.push({
      testName,
      category,
      vulnerable,
      cwe,
      file: javaFile,
      sha256: sha256File(javaFile),
    });
  }

  if (missing.length > 0) {
    console.warn(`[manifest-builder] WARNING: ${missing.length} test cases not found on disk`);
  }

  const manifest = {
    generated:   new Date().toISOString(),
    phase:       4,
    corpus:      'OWASP Benchmark Java v1.2',
    total:       entries.length,
    missing:     missing.length,
    environment: ENVIRONMENT,
    entries,
  };

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2));
  console.log(`[manifest-builder] Wrote ${entries.length} entries → ${MANIFEST_PATH}`);
  if (missing.length > 0) {
    console.log(`[manifest-builder] Missing files: ${JSON.stringify(missing)}`);
  }
}

buildManifest();
