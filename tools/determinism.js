'use strict';
/**
 * Determinism check: two runs over the same pinned commit must produce the same
 * evidence, once wall-clock, timestamps, artifact sizes and output paths are
 * removed. Anything left differing is real nondeterminism and must be explained,
 * not tolerated.
 */
const fs = require('fs');
const path = require('path');

const VOLATILE = new Set(['startedAt', 'finishedAt', 'totalWallClockMs', 'artifactBytes', 'wallClockMs', 'dbBytes', 'dbDiscardedBytes', 'artifactBytes', 'peakRamMB', 'out']);

function normalize(v) {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v).sort()) {
      if (VOLATILE.has(k)) continue;
      o[k] = normalize(v[k]);
    }
    return o;
  }
  return v;
}

const load = (dir) => JSON.parse(fs.readFileSync(path.join(dir, 'expediente.json'), 'utf8'));
const A0 = load(process.argv[2]);
const B0 = load(process.argv[3]);

/** Erase this run's own output directory from any recorded path. */
const scrubRun = (obj, runName) => {
  if (typeof obj === 'string') return obj.split('out' + path.sep + runName).join('out' + path.sep + '<RUN>');
  if (Array.isArray(obj)) return obj.map((v) => scrubRun(v, runName));
  if (obj && typeof obj === 'object') {
    const o = {};
    for (const k of Object.keys(obj)) o[k] = scrubRun(obj[k], runName);
    return o;
  }
  return obj;
};

const a = normalize(scrubRun(A0, A0.name));
const b = normalize(scrubRun(B0, B0.name));

// The run name is the only intentional difference between two runs of one target.
delete a.name; delete b.name;

const sa = JSON.stringify(a, null, 2);
const sb = JSON.stringify(b, null, 2);

if (sa === sb) {
  console.log('DETERMINISTIC: both runs produce byte-identical evidence after removing volatile fields.');
  console.log(`  candidates=${a.candidates.length} observations=${a.observations.length} nonProduction=${a.nonProductionSignals.length}`);
  console.log(`  verdict=${a.auditVerdict.verdict} analysis=${a.auditVerdict.analysisState} canClaimClean=${a.auditVerdict.canClaimClean}`);
  console.log(`  tool verdicts: ${Object.entries(a.tools).map(([k, v]) => `${k}=${v.status}/${v.verdict}`).join('  ')}`);
  process.exit(0);
}

const la = sa.split('\n'); const lb = sb.split('\n');
const diffs = [];
for (let i = 0, j = 0; i < la.length || j < lb.length;) {
  if (la[i] === lb[j]) { i++; j++; continue; }
  diffs.push(`  line ${i + 1}:\n    A: ${String(la[i]).trim().slice(0, 160)}\n    B: ${String(lb[j]).trim().slice(0, 160)}`);
  i++; j++;
  if (diffs.length >= 25) { diffs.push('  ...(truncated)'); break; }
}
console.log(`NONDETERMINISTIC: ${diffs.length} divergence(s)\n` + diffs.join('\n'));
process.exit(1);
