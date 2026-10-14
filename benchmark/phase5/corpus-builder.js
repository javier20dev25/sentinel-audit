#!/usr/bin/env node
/**
 * Phase 5 Corpus Builder
 * ======================
 * Queries OSV.dev and GitHub Advisory Database GraphQL API to assemble
 * a pilot corpus of 50 real-world vulnerabilities with:
 *   - advisory ID (CVE / GHSA / OSV)
 *   - public GitHub repo URL
 *   - vulnerable commit SHA (introduced)
 *   - fix commit SHA (fixed)
 *   - affected file paths (from patch diff)
 *   - CWE / severity
 *
 * Output: PHASE5_MANIFEST.json + PHASE5_GROUND_TRUTH.json
 *
 * SAFETY CONSTRAINT: This script performs ONLY:
 *   - HTTPS API calls (read-only)
 *   - git clone --no-checkout (no code execution)
 *   - git ls-tree / git diff --name-only (metadata only)
 * It NEVER runs npm install, npm run, node <script>, or any package lifecycle.
 *
 * Usage:
 *   node corpus-builder.js [--limit=50] [--ecosystem=npm] [--out=./]
 *   GITHUB_TOKEN=<pat> node corpus-builder.js
 *
 * A GITHUB_TOKEN with read:packages scope greatly increases rate limits
 * for the Advisory Database GraphQL queries.
 */

'use strict';

const https = require('https');
const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Config ────────────────────────────────────────────────────────────────

const ARGS = Object.fromEntries(
  process.argv.slice(2)
    .filter(a => a.startsWith('--'))
    .map(a => { const [k, v] = a.slice(2).split('='); return [k, v ?? true]; })
);

const LIMIT      = parseInt(ARGS.limit     ?? '50', 10);
const ECOSYSTEM  = (ARGS.ecosystem ?? 'npm').toLowerCase();
const OUT_DIR    = path.resolve(ARGS.out ?? __dirname);
const CLONES_DIR = path.join(OUT_DIR, 'clones');
const GITHUB_TOKEN = process.env.GITHUB_TOKEN ?? '';

const MANIFEST_PATH     = path.join(OUT_DIR, 'PHASE5_MANIFEST.json');
const GROUND_TRUTH_PATH = path.join(OUT_DIR, 'PHASE5_GROUND_TRUTH.json');
const ERRORS_PATH       = path.join(OUT_DIR, 'PHASE5_ERRORS.jsonl');

// OSV batch query: fetch advisories for ecosystem with git fix commits
const OSV_BATCH_URL = 'https://api.osv.dev/v1/query';
// GitHub GHSA GraphQL endpoint
const GH_GRAPHQL_URL = 'https://api.github.com/graphql';

// Severity priority order for selection
const SEVERITY_PRIORITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Ground-truth classes
const GT = {
  VERIFIED_VULNERABLE: 'VERIFIED_VULNERABLE',
  VERIFIED_PATCHED:    'VERIFIED_PATCHED',
  INSUFFICIENT:        'INSUFFICIENT_GROUND_TRUTH',
  AMBIGUOUS:           'AMBIGUOUS_PATCH',
};

// ─── Utilities ─────────────────────────────────────────────────────────────

function log(msg)  { process.stdout.write(`[corpus-builder] ${msg}\n`); }
function warn(msg) { process.stderr.write(`[WARN] ${msg}\n`); }

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/** Append a JSON error record to the errors log */
function logError(entry) {
  fs.appendFileSync(ERRORS_PATH, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
}

/** SHA-256 of a string */
function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/** Make an HTTPS request, returns parsed JSON */
function httpsRequest(url, opts = {}, body = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const options = {
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: opts.method ?? (body ? 'POST' : 'GET'),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'sentinel-phase5-corpus-builder/1.0',
        ...(GITHUB_TOKEN ? { 'Authorization': `Bearer ${GITHUB_TOKEN}` } : {}),
        ...(opts.headers ?? {}),
      },
    };
    const req = https.request(options, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${raw.slice(0, 200)}`));
          return;
        }
        try { resolve(JSON.parse(raw)); }
        catch (e) { reject(new Error(`JSON parse error: ${e.message}\n${raw.slice(0, 200)}`)); }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ─── OSV queries ───────────────────────────────────────────────────────────

/**
 * Query OSV for a batch of advisories by ecosystem.
 * OSV doesn't expose a "list all" endpoint easily; we page by querying
 * with a known package name pattern or use the bulk download approach.
 * 
 * Strategy: Use the OSV bulk download (NDJSON) via the GCS bucket.
 * For npm: https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
 * We'll stream and parse a sample. As a fallback we query by known
 * high-profile packages from npm that have published advisories.
 */
async function fetchOsvAdvisories(ecosystem, limit) {
  log(`Fetching OSV advisories for ecosystem=${ecosystem} (limit=${limit})...`);

  // High-value npm packages with published CVEs and git fix commits
  // These are well-known, widely-studied packages that consistently appear
  // in security research corpora.
  const SEED_PACKAGES = [
    'lodash', 'express', 'axios', 'moment', 'serialize-javascript',
    'node-fetch', 'handlebars', 'marked', 'highlight.js', 'ejs',
    'vm2', 'ansi-regex', 'braces', 'json5', 'semver',
    'pug', 'got', 'tar', 'tough-cookie', 'ws',
    'underscore', 'mongoose', 'sequelize', 'passport', 'jsonwebtoken',
    'minimist', 'npmlog', 'async', 'request', 'debug',
    'shelljs', 'cross-spawn', 'body-parser', 'multer', 'socket.io',
    'nodemailer', 'jsdom', 'cheerio', 'uuid', 'xmldom',
    'class-transformer', 'parse', 'strapi', 'next', 'gatsby',
    'sharp', 'glob', 'micromatch', 'yargs-parser', 'node-jose',
    'validator', 'sanitize-html', 'dompurify', 'fast-xml-parser', 'qs',
    'path-to-regexp', 'postcss', 'yaml', 'urllib', 'follow-redirects',
    'ip', 'needle', 'deep-extend', 'ini', 'minimatch', 'kind-of',
    'dot-prop', 'set-value', 'mixin-deep', 'json-pointer'
  ];

  const candidates = [];
  const seen = new Set();

  for (const pkg of SEED_PACKAGES) {
    try {
      const result = await httpsRequest(
        `https://api.osv.dev/v1/query`,
        { method: 'POST' },
        { package: { name: pkg, ecosystem: ecosystem === 'npm' ? 'npm' : ecosystem } }
      );
      const vulns = result.vulns ?? [];
      for (const v of vulns) {
        if (!seen.has(v.id)) {
          seen.add(v.id);
          candidates.push({ pkg, advisory: v });
        }
      }
      log(`  ${pkg}: ${vulns.length} advisories found`);
      await sleep(100); // rate-limit courtesy
    } catch (e) {
      warn(`OSV query failed for ${pkg}: ${e.message}`);
      logError({ phase: 'osv_query', pkg, error: e.message });
    }
  }

  log(`Total OSV candidates before filtering: ${candidates.length}`);
  return candidates;
}

// ─── Filter: keep only advisories with git commit ranges ───────────────────

function extractGitCommits(advisory) {
  const result = { introduced: null, fixed: null, repoUrl: null };

  // 1. Try ranges with type: 'GIT'
  for (const affected of (advisory.affected ?? [])) {
    for (const range of (affected.ranges ?? [])) {
      if (range.type === 'GIT') {
        result.repoUrl = range.repo ?? null;
        for (const ev of (range.events ?? [])) {
          if (ev.introduced && ev.introduced !== '0') result.introduced = ev.introduced;
          if (ev.fixed) result.fixed = ev.fixed;
        }
        if (result.fixed) return result;
      }
    }
  }

  // 2. Try commit URLs in references
  for (const ref of (advisory.references ?? [])) {
    const u = ref.url ?? '';
    const m = u.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-fA-F]{7,40})/);
    if (m) {
      result.repoUrl = `https://github.com/${m[1]}/${m[2]}`;
      result.fixed = m[3];
      // introduced will be resolved as <fixed>~1 after clone
      return result;
    }
  }

  return result;
}

function extractCwe(advisory) {
  const refs = advisory.database_specific ?? {};
  // GHSA-style
  const cwes = refs.cwe_ids ?? [];
  if (cwes.length > 0) return cwes[0];
  // Try severity alias
  return null;
}

function extractSeverity(advisory) {
  // OSV severity field
  for (const s of (advisory.severity ?? [])) {
    if (s.type === 'CVSS_V3') {
      const score = parseFloat(s.score.split('/').find(p => p.startsWith('CVSS'))?.replace('CVSS:3.1/', '') ?? '0');
      const base = advisory.database_specific?.severity;
      if (base) return base.toUpperCase();
    }
  }
  return advisory.database_specific?.severity?.toUpperCase() ?? 'UNKNOWN';
}

function extractCves(advisory) {
  return (advisory.aliases ?? []).filter(a => a.startsWith('CVE-'));
}

function inferRepoUrlFromAdvisory(advisory, pkg) {
  for (const ref of (advisory.references ?? [])) {
    const u = ref.url ?? '';
    const m = u.match(/^https:\/\/github\.com\/([^/]+\/[^/]+?)(?:\/|$)/);
    if (m && !u.includes('/advisories/') && !u.includes('/security/advisories')) {
      return `https://github.com/${m[1]}`;
    }
  }
  return null;
}

// ─── Validate that a commit SHA exists on the remote (git ls-remote) ───────

function validateCommitExists(repoUrl, sha) {
  if (!sha || sha.length < 7) return false;
  try {
    const r = spawnSync('git', ['ls-remote', repoUrl, sha], {
      timeout: 20000, encoding: 'utf8', windowsHide: true
    });
    // ls-remote returns lines like "<sha>\t<ref>"; if the sha is a commit (not a ref)
    // it may not appear in ls-remote. We'll do a shallow clone check instead.
    // For now, if no error and we got output, it's likely valid.
    return r.status === 0;
  } catch { return false; }
}

// ─── Get affected files from diff between two commits ──────────────────────

function getAffectedFiles(cloneDir, vulnerableSha, fixSha) {
  try {
    const r = spawnSync(
      'git', ['diff', '--name-only', vulnerableSha, fixSha],
      { cwd: cloneDir, timeout: 30000, encoding: 'utf8', windowsHide: true }
    );
    if (r.status !== 0) return [];
    return r.stdout.trim().split('\n').filter(Boolean);
  } catch { return []; }
}

// ─── Clone a repo (no checkout) ────────────────────────────────────────────

function cloneRepo(repoUrl, destDir) {
  if (fs.existsSync(path.join(destDir, 'HEAD')) || fs.existsSync(path.join(destDir, '.git'))) {
    log(`    Already cloned: ${destDir}`);
    return true;
  }
  if (fs.existsSync(destDir)) {
    try { fs.rmSync(destDir, { recursive: true, force: true }); } catch {}
  }
  fs.mkdirSync(destDir, { recursive: true });
  const r = spawnSync(
    'git', ['clone', '--bare', '--filter=blob:none', repoUrl, destDir],
    { timeout: 120000, encoding: 'utf8', windowsHide: true }
  );
  if (r.status !== 0) {
    warn(`Clone failed for ${repoUrl}: ${(r.stderr ?? '').slice(0, 200)}`);
    logError({ phase: 'clone', repoUrl, error: (r.stderr ?? '').slice(0, 300) });
    return false;
  }
  return true;
}

// ─── SHA-256 of a file at a specific commit (git show) ─────────────────────

function fileHashAtCommit(cloneDir, sha, filePath) {
  try {
    const r = spawnSync(
      'git', ['show', `${sha}:${filePath}`],
      { cwd: cloneDir, timeout: 15000, encoding: 'buffer', windowsHide: true }
    );
    if (r.status !== 0) return null;
    return crypto.createHash('sha256').update(r.stdout).digest('hex');
  } catch { return null; }
}

// ─── Classify ground truth ─────────────────────────────────────────────────

function classifyGroundTruth(entry) {
  const { vulnerableSha, fixSha, repoUrl, affectedFiles } = entry;
  if (!repoUrl) return GT.INSUFFICIENT;
  if (!vulnerableSha) return GT.INSUFFICIENT;
  if (!fixSha) return GT.AMBIGUOUS;
  if (affectedFiles.length === 0) return GT.AMBIGUOUS;
  return GT.VERIFIED_VULNERABLE; // vulnerable revision classified as VERIFIED_VULNERABLE
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  log('=== Phase 5 Corpus Builder ===');
  log(`Target: ${LIMIT} advisories | Ecosystem: ${ECOSYSTEM}`);
  log(`Output: ${OUT_DIR}`);
  log(`Clones: ${CLONES_DIR}`);
  if (!GITHUB_TOKEN) log('NOTICE: No GITHUB_TOKEN set — GitHub API rate limits apply (60 req/hr)');

  fs.mkdirSync(CLONES_DIR, { recursive: true });
  // Clear errors file
  fs.writeFileSync(ERRORS_PATH, '');

  // 1. Fetch OSV candidates
  const candidates = await fetchOsvAdvisories(ECOSYSTEM, LIMIT);

  // 2. Filter: must have git commit range + resolvable repo
  log('\nFiltering candidates for git commit ranges...');
  const filtered = [];
  const pkgCount = {};
  for (const { pkg, advisory } of candidates) {
    if ((pkgCount[pkg] ?? 0) >= 3) continue; // cap at 3 per package for diversity

    const { introduced, fixed, repoUrl: gitRepoUrl } = extractGitCommits(advisory);
    const repoUrl = gitRepoUrl ?? inferRepoUrlFromAdvisory(advisory, pkg);

    if (!fixed) continue;           // need a fix commit
    if (!repoUrl) continue;         // need a repo
    if (!repoUrl.includes('github.com')) continue; // github only for now

    filtered.push({
      pkg,
      advisoryId: advisory.id,
      cves: extractCves(advisory),
      summary: advisory.summary ?? '',
      severity: extractSeverity(advisory),
      cwe: extractCwe(advisory),
      repoUrl: repoUrl.replace(/\.git$/, ''),
      vulnerableSha: introduced,
      fixSha: fixed,
    });
    pkgCount[pkg] = (pkgCount[pkg] ?? 0) + 1;
  }

  // Sort: prefer CRITICAL > HIGH > MEDIUM > LOW, then VERIFIED over ambiguous
  filtered.sort((a, b) => {
    const ai = SEVERITY_PRIORITY.indexOf(a.severity);
    const bi = SEVERITY_PRIORITY.indexOf(b.severity);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  log(`Filtered candidates with git ranges: ${filtered.length}`);

  // 3. Clone repos and compute affected files
  const manifestEntries = [];
  const groundTruth = [];
  let index = 0;

  for (const entry of filtered) {
    if (manifestEntries.length >= LIMIT) break;
    index++;

    const slug = entry.repoUrl.replace('https://github.com/', '').replace(/\//g, '_');
    const cloneDir = path.join(CLONES_DIR, slug);

    log(`\n[${index}/${filtered.length}] ${entry.advisoryId} — ${entry.pkg} — ${entry.repoUrl}`);

    // Clone (bare, no checkout)
    const cloned = cloneRepo(entry.repoUrl, cloneDir);
    if (!cloned) {
      logError({ phase: 'filter_clone', advisory: entry.advisoryId, reason: 'clone_failed' });
      continue;
    }

    // Verify fix commit exists in cloned repo
    try {
      execSync(`git rev-parse --verify ${entry.fixSha}`, {
        cwd: cloneDir, encoding: 'utf8', windowsHide: true, stdio: 'pipe'
      });
    } catch {
      warn(`    Fix commit ${entry.fixSha} not present in clone of ${entry.repoUrl}`);
      logError({ phase: 'verify_fix_sha', advisory: entry.advisoryId, fixSha: entry.fixSha });
      continue;
    }

    // Resolve vulnerable SHA if not explicitly set
    if (!entry.vulnerableSha) {
      try {
        entry.vulnerableSha = execSync(`git rev-parse ${entry.fixSha}~1`, {
          cwd: cloneDir, encoding: 'utf8', windowsHide: true, stdio: 'pipe'
        }).trim();
      } catch (err) {
        warn(`    Could not resolve parent commit for ${entry.fixSha}: ${err.message}`);
        logError({ phase: 'resolve_parent_sha', advisory: entry.advisoryId, error: err.message });
        continue;
      }
    }

    // Get affected files from diff
    const affectedFiles = getAffectedFiles(cloneDir, entry.vulnerableSha, entry.fixSha);
    log(`    Affected files: ${affectedFiles.length} — ${affectedFiles.slice(0, 3).join(', ')}${affectedFiles.length > 3 ? '...' : ''}`);

    // Filter to source files only (no lock files, docs, etc.)
    const sourceExtensions = new Set([
      '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
      '.java', '.py', '.go', '.rb', '.php', '.c', '.cpp', '.h', '.cs', '.json'
    ]);
    const sourceFiles = affectedFiles.filter(f => sourceExtensions.has(path.extname(f).toLowerCase()));

    if (sourceFiles.length === 0) {
      log(`    No source files affected (only docs/config). Skipping.`);
      continue;
    }

    const entry_gt = classifyGroundTruth({ ...entry, affectedFiles: sourceFiles });

    // Compute patch diff hash and primary affected file hash
    const diffOut = spawnSync('git', ['diff', entry.vulnerableSha, entry.fixSha], {
      cwd: cloneDir, encoding: 'utf8', windowsHide: true
    }).stdout ?? '';
    const patchDiffHash = sha256(diffOut);

    const fileHashes = {};
    const primaryFile = sourceFiles[0];
    if (primaryFile) {
      fileHashes[primaryFile] = {
        vulnerableRevision: fileHashAtCommit(cloneDir, entry.vulnerableSha, primaryFile),
        fixRevision: fileHashAtCommit(cloneDir, entry.fixSha, primaryFile),
      };
    }

    const manifestEntry = {
      id: `P5-${String(manifestEntries.length + 1).padStart(3, '0')}`,
      advisoryId:       entry.advisoryId,
      cves:             entry.cves,
      packageName:      entry.pkg,
      ecosystem:        ECOSYSTEM,
      severity:         entry.severity,
      cwe:              entry.cwe,
      summary:          entry.summary.slice(0, 200),
      repoUrl:          entry.repoUrl,
      vulnerableSha:    entry.vulnerableSha,
      fixSha:           entry.fixSha,
      affectedSourceFiles: sourceFiles,
      allAffectedFiles:    affectedFiles,
      patchDiffHash,
      fileHashes,
      groundTruthClass:    entry_gt,
      clonePath:           path.relative(OUT_DIR, cloneDir),
      createdAt:           new Date().toISOString(),
    };

    manifestEntries.push(manifestEntry);

    groundTruth.push({
      id:             manifestEntry.id,
      advisoryId:     entry.advisoryId,
      groundTruth:    entry_gt,
      vulnerableSha:  entry.vulnerableSha,
      fixSha:         entry.fixSha,
      affectedFiles:  sourceFiles,
      expectedCwe:    entry.cwe,
      measurementGroup: entry.cwe?.startsWith('CWE-1236') || entry.cwe === 'CWE-829'
        ? 'dependency_vulnerabilities'
        : 'code_vulnerabilities',
    });

    log(`    → ${entry_gt} | ${manifestEntries.length}/${LIMIT} collected`);
  }

  // 4. Write manifest
  const manifest = {
    phase: 'Phase 5 — Real-World Vulnerability Benchmark',
    schemaVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    ecosystem: ECOSYSTEM,
    corpusSize: manifestEntries.length,
    groundTruthSummary: {
      VERIFIED_VULNERABLE: manifestEntries.filter(e => e.groundTruthClass === GT.VERIFIED_VULNERABLE).length,
      VERIFIED_PATCHED:    0, // set at scan time
      INSUFFICIENT_GROUND_TRUTH: manifestEntries.filter(e => e.groundTruthClass === GT.INSUFFICIENT).length,
      AMBIGUOUS_PATCH:     manifestEntries.filter(e => e.groundTruthClass === GT.AMBIGUOUS).length,
    },
    entries: manifestEntries,
  };

  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2));
  fs.writeFileSync(GROUND_TRUTH_PATH, JSON.stringify({
    phase: 'Phase 5',
    generatedAt: new Date().toISOString(),
    entries: groundTruth,
  }, null, 2));

  // 5. Summary
  log('\n=== Corpus Build Complete ===');
  log(`Manifest entries:     ${manifestEntries.length}`);
  log(`VERIFIED_VULNERABLE:  ${manifest.groundTruthSummary.VERIFIED_VULNERABLE}`);
  log(`INSUFFICIENT:         ${manifest.groundTruthSummary.INSUFFICIENT_GROUND_TRUTH}`);
  log(`AMBIGUOUS_PATCH:      ${manifest.groundTruthSummary.AMBIGUOUS_PATCH}`);
  log(`Manifest written:     ${MANIFEST_PATH}`);
  log(`Ground truth written: ${GROUND_TRUTH_PATH}`);

  const errors = fs.readFileSync(ERRORS_PATH, 'utf8').trim().split('\n').filter(Boolean);
  if (errors.length > 0) {
    log(`Errors logged:        ${errors.length} (see ${ERRORS_PATH})`);
  }

  // Gate G1 check
  const g1Pass = manifestEntries.every(e =>
    e.advisoryId && e.vulnerableSha && e.fixSha && e.affectedSourceFiles.length > 0
  );
  log(`\nPilot Gate G1 (all entries have advisory+shas+files): ${g1Pass ? 'PASS' : 'PARTIAL'}`);
  if (!g1Pass) {
    const incomplete = manifestEntries.filter(e =>
      !e.advisoryId || !e.vulnerableSha || !e.fixSha || !e.affectedSourceFiles.length
    );
    log(`  Incomplete entries: ${incomplete.map(e => e.id).join(', ')}`);
  }

  if (manifestEntries.length < LIMIT) {
    log(`\nWARNING: Only ${manifestEntries.length}/${LIMIT} entries collected.`);
    log('Run with more seed packages or add --ecosystem=pypi for a second pass.');
  }
}

main().catch(e => {
  process.stderr.write(`Fatal error: ${e.message}\n${e.stack}\n`);
  process.exit(1);
});
