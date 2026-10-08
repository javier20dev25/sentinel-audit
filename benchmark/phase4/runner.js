/**
 * Phase 4 — OWASP Benchmark Java v1.2 Runner
 * Language-Aware Routing: Java → Semgrep (p/java)
 * AI DISABLED. LLM calls = 0.
 *
 * Architecture:
 *   8 workers, each pulling from a shared queue.
 *   Per file: semgrep scan --config p/java → normalize → classify verdict.
 *   Results streamed to PHASE4_RESULTS.jsonl (append-only).
 *   Progress printed to stdout every PROGRESS_INTERVAL items.
 */
'use strict';

const fs           = require('fs');
const path         = require('path');
const { execFile } = require('child_process');
const os           = require('os');

const {
  PHASE4_DIR, WORKERS, TIMEOUT_MS, SEMGREP_CONFIG,
  ENVIRONMENT, VERDICT, AI_ENABLED,
} = require('./config');

const MANIFEST_PATH = path.join(PHASE4_DIR, 'PHASE4_MANIFEST.json');
const RESULTS_PATH  = path.join(PHASE4_DIR, 'PHASE4_RESULTS.jsonl');
const ENV_PATH      = path.join(PHASE4_DIR, 'PHASE4_ENVIRONMENT.json');
const PROGRESS_INTERVAL = 50;

// ── Sanity check ─────────────────────────────────────────────────────────────
if (AI_ENABLED) {
  console.error('FATAL: AI_ENABLED must be false for Phase 4.');
  process.exit(1);
}

// ── Load manifest ─────────────────────────────────────────────────────────────
if (!fs.existsSync(MANIFEST_PATH)) {
  console.error('FATAL: PHASE4_MANIFEST.json not found. Run manifest-builder.js first.');
  process.exit(1);
}

const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
const allEntries = manifest.entries;
console.log(`[runner] Loaded manifest: ${allEntries.length} entries`);
console.log(`[runner] AI_ENABLED=${AI_ENABLED} | Workers=${WORKERS} | Timeout=${TIMEOUT_MS}ms`);
console.log(`[runner] Semgrep config: ${SEMGREP_CONFIG}`);

// ── Write frozen environment ──────────────────────────────────────────────────
fs.writeFileSync(ENV_PATH, JSON.stringify(ENVIRONMENT, null, 2));
console.log(`[runner] Wrote environment freeze → ${ENV_PATH}`);

// ── Resume support ────────────────────────────────────────────────────────────
const done = new Set();
if (fs.existsSync(RESULTS_PATH)) {
  const existing = fs.readFileSync(RESULTS_PATH, 'utf8').trim().split('\n').filter(Boolean);
  for (const line of existing) {
    try {
      const r = JSON.parse(line);
      if (r.testName) done.add(r.testName);
    } catch { /* skip corrupt lines */ }
  }
  console.log(`[runner] Resume: ${done.size} already completed, ${allEntries.length - done.size} remaining`);
}

const queue = allEntries.filter(e => !done.has(e.testName));
if (queue.length === 0) {
  console.log('[runner] All entries already processed. Nothing to do.');
  process.exit(0);
}

// ── Shared state ─────────────────────────────────────────────────────────────
let queueIdx   = 0;
let completed  = done.size;
let total      = allEntries.length;
const startTs  = Date.now();
const writeStream = fs.createWriteStream(RESULTS_PATH, { flags: 'a' });

const counters = {
  TRUE_POSITIVE:    0,
  TRUE_NEGATIVE:    0,
  FALSE_POSITIVE:   0,
  FALSE_NEGATIVE:   0,
  UNSCANNABLE:      0,
  ROUTING_ERROR:    0,
  SPECIALIST_ERROR: 0,
  TIMEOUT:          0,
};

// Pre-populate counters from already-done results
if (done.size > 0) {
  const existing = fs.readFileSync(RESULTS_PATH, 'utf8').trim().split('\n').filter(Boolean);
  for (const line of existing) {
    try {
      const r = JSON.parse(line);
      if (r.verdict && counters[r.verdict] !== undefined) counters[r.verdict]++;
    } catch { /* ignore */ }
  }
}

// ── Mutex for stream writes ───────────────────────────────────────────────────
let writeLock = Promise.resolve();
function writeResult(obj) {
  writeLock = writeLock.then(() => new Promise(resolve => {
    writeStream.write(JSON.stringify(obj) + '\n', resolve);
  }));
  return writeLock;
}

// ── Semgrep invocation ────────────────────────────────────────────────────────
function runSemgrep(javaFile) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const args = [
      'scan',
      '--config', SEMGREP_CONFIG,
      '--json',
      '--quiet',
      '--metrics=off',
      '--disable-version-check',
      '--no-git-ignore',
      '--',
      javaFile,
    ];

    execFile('semgrep', args, { timeout: TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      const ms = Date.now() - t0;

      // semgrep exits 1 when findings are present — that is NOT an error.
      // It exits with a non-zero code != 1 for real errors.
      const exitCode = err ? err.code : 0;

      if (err && exitCode === 'ETIMEDOUT') {
        return resolve({ ok: false, reason: 'TIMEOUT', ms, findings: [] });
      }
      if (err && exitCode !== 1 && exitCode !== 0) {
        return resolve({ ok: false, reason: 'SPECIALIST_ERROR', ms, findings: [], exitCode, stderr: stderr.slice(0, 500) });
      }

      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch (e) {
        return resolve({ ok: false, reason: 'SPECIALIST_ERROR', ms, findings: [], parseError: e.message });
      }

      const findings = (parsed.results || []).map(r => ({
        rule:     r.check_id,
        file:     r.path,
        line:     r.start && r.start.line,
        severity: (r.extra && r.extra.severity) ? r.extra.severity.toUpperCase() : 'UNKNOWN',
        message:  r.extra && r.extra.message ? r.extra.message.slice(0, 200) : '',
      }));

      return resolve({ ok: true, ms, findings });
    });
  });
}

// ── Verdict classification ────────────────────────────────────────────────────
function classify(vulnerable, flagged) {
  if (vulnerable && flagged)  return VERDICT.TRUE_POSITIVE;
  if (!vulnerable && flagged) return VERDICT.FALSE_POSITIVE;
  if (vulnerable && !flagged) return VERDICT.FALSE_NEGATIVE;
  return VERDICT.TRUE_NEGATIVE;
}

// ── Progress printer ──────────────────────────────────────────────────────────
function printProgress() {
  const elapsed = ((Date.now() - startTs) / 1000).toFixed(1);
  const pct = ((completed / total) * 100).toFixed(1);
  const tp = counters.TRUE_POSITIVE;
  const tn = counters.TRUE_NEGATIVE;
  const fp = counters.FALSE_POSITIVE;
  const fn = counters.FALSE_NEGATIVE;
  const err = counters.SPECIALIST_ERROR + counters.TIMEOUT + counters.UNSCANNABLE + counters.ROUTING_ERROR;
  process.stdout.write(
    `\r[runner] ${completed}/${total} (${pct}%) | TP=${tp} TN=${tn} FP=${fp} FN=${fn} ERR=${err} | ${elapsed}s`
  );
}

// ── Worker ────────────────────────────────────────────────────────────────────
async function worker(id) {
  while (true) {
    // Grab next item atomically
    const idx = queueIdx++;
    if (idx >= queue.length) break;

    const entry = queue[idx];
    const { testName, category, vulnerable, cwe, file, sha256 } = entry;

    let result;
    const t0 = Date.now();

    // LANGUAGE DETECT: Java (hardcoded — all OWASP test cases are Java)
    const language = 'java';

    // ROUTING: Route to Semgrep Java (only specialist available)
    const specialist = 'semgrep';

    try {
      result = await runSemgrep(file);
    } catch (e) {
      result = { ok: false, reason: 'SPECIALIST_ERROR', ms: Date.now() - t0, findings: [], exception: e.message };
    }

    let verdict;
    if (!result.ok) {
      verdict = result.reason === 'TIMEOUT' ? VERDICT.TIMEOUT
              : result.reason === 'SPECIALIST_ERROR' ? VERDICT.SPECIALIST_ERROR
              : VERDICT.UNSCANNABLE;
    } else {
      const flagged = result.findings.length > 0;
      verdict = classify(vulnerable, flagged);
    }

    counters[verdict]++;
    completed++;

    const record = {
      testName,
      category,
      vulnerable,
      cwe,
      file,
      sha256,
      language,
      specialist,
      verdict,
      flagged:   result.ok ? result.findings.length > 0 : null,
      findings:  result.ok ? result.findings : [],
      ms:        result.ms,
      ...(result.ok ? {} : { errorReason: result.reason, exitCode: result.exitCode, stderr: result.stderr }),
      ts: new Date().toISOString(),
    };

    await writeResult(record);

    if (completed % PROGRESS_INTERVAL === 0 || completed === total) {
      printProgress();
    }
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`[runner] Starting ${WORKERS} workers over ${queue.length} queued items...`);
  printProgress();

  const workers = Array.from({ length: WORKERS }, (_, i) => worker(i));
  await Promise.all(workers);

  writeStream.end();
  await new Promise(r => writeStream.on('finish', r));

  const elapsed = ((Date.now() - startTs) / 1000).toFixed(2);
  process.stdout.write('\n');
  console.log('[runner] ── Campaign complete ──────────────────────────────────');
  console.log(`[runner] Wall clock:  ${elapsed}s`);
  console.log(`[runner] Total:       ${completed}`);
  console.log(`[runner] TRUE_POSITIVE:    ${counters.TRUE_POSITIVE}`);
  console.log(`[runner] TRUE_NEGATIVE:    ${counters.TRUE_NEGATIVE}`);
  console.log(`[runner] FALSE_POSITIVE:   ${counters.FALSE_POSITIVE}`);
  console.log(`[runner] FALSE_NEGATIVE:   ${counters.FALSE_NEGATIVE}`);
  console.log(`[runner] SPECIALIST_ERROR: ${counters.SPECIALIST_ERROR}`);
  console.log(`[runner] TIMEOUT:          ${counters.TIMEOUT}`);
  console.log(`[runner] UNSCANNABLE:      ${counters.UNSCANNABLE}`);
  console.log(`[runner] Results → ${RESULTS_PATH}`);
}

main().catch(e => {
  console.error('[runner] FATAL:', e);
  process.exit(1);
});
