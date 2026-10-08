'use strict';

const fs = require('fs');

function loadCorpusData(jsonlPath) {
  const lines = fs.readFileSync(jsonlPath, 'utf8').trim().split('\n');
  const packages = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const r = JSON.parse(line);
    const candidates = r.candidates?.total ?? r.signals?.rawCandidatesTotal ?? r.signals?.rawAlertsTotal ?? 0;
    const escalations = r.hybrid?.escalationCount || 0;
    packages.push({
      id: r.target?.targetId || 'unknown',
      candidates,
      escalations
    });
  }
  return packages;
}

const p2Packages = loadCorpusData('C:/Users/sleyt/sentinel-audit/benchmark/phase2/PHASE2_RESULTS.jsonl');
const p3Packages = loadCorpusData('C:/Users/sleyt/sentinel-audit/benchmark/phase3/PHASE3_RESULTS.jsonl');

console.log(`Phase 2A packages: ${p2Packages.length}`);
console.log(`Phase 3 packages:  ${p3Packages.length}`);

// Point estimates
function calcRate(pkgs) {
  let totalCand = 0;
  let totalEsc = 0;
  for (const p of pkgs) {
    totalCand += p.candidates;
    totalEsc += p.escalations;
  }
  return totalCand > 0 ? (totalEsc / totalCand) : 0;
}

const p2Rate = calcRate(p2Packages);
const p3Rate = calcRate(p3Packages);
const observedDelta = (p3Rate - p2Rate) * 100;

console.log(`Phase 2A Point Rate: ${(p2Rate * 100).toFixed(4)}%`);
console.log(`Phase 3 Point Rate:  ${(p3Rate * 100).toFixed(4)}%`);
console.log(`Observed Delta:      ${observedDelta.toFixed(4)} pp`);

// Clustered Bootstrap (resampling packages with replacement)
const B = 10000;
const p2BootstrapRates = new Float64Array(B);
const p3BootstrapRates = new Float64Array(B);
const deltaBootstrap = new Float64Array(B);

// Simple deterministic PRNG for exact reproducibility
let seed = 42;
function rand() {
  seed = (seed * 1664525 + 1013904223) % 4294967296;
  return seed / 4294967296;
}

const n2 = p2Packages.length;
const n3 = p3Packages.length;

for (let b = 0; b < B; b++) {
  // Resample Phase 2A
  let cand2 = 0, esc2 = 0;
  for (let i = 0; i < n2; i++) {
    const idx = Math.floor(rand() * n2);
    cand2 += p2Packages[idx].candidates;
    esc2 += p2Packages[idx].escalations;
  }
  const r2 = cand2 > 0 ? (esc2 / cand2) : 0;
  p2BootstrapRates[b] = r2 * 100;

  // Resample Phase 3
  let cand3 = 0, esc3 = 0;
  for (let i = 0; i < n3; i++) {
    const idx = Math.floor(rand() * n3);
    cand3 += p3Packages[idx].candidates;
    esc3 += p3Packages[idx].escalations;
  }
  const r3 = cand3 > 0 ? (esc3 / cand3) : 0;
  p3BootstrapRates[b] = r3 * 100;

  deltaBootstrap[b] = (r3 - r2) * 100;
}

function quantile(arr, q) {
  const sorted = Array.from(arr).sort((a, b) => a - b);
  const pos = (sorted.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (sorted[base + 1] !== undefined) {
    return sorted[base] + rest * (sorted[base + 1] - sorted[base]);
  }
  return sorted[base];
}

const p2CI = [quantile(p2BootstrapRates, 0.025), quantile(p2BootstrapRates, 0.975)];
const p3CI = [quantile(p3BootstrapRates, 0.025), quantile(p3BootstrapRates, 0.975)];
const deltaCI = [quantile(deltaBootstrap, 0.025), quantile(deltaBootstrap, 0.975)];

console.log('\n=== CLUSTERED BOOTSTRAP RESULTS (B=10,000) ===');
console.log(`Phase 2A Rate 95% CI: [${p2CI[0].toFixed(3)}%, ${p2CI[1].toFixed(3)}%]`);
console.log(`Phase 3 Rate 95% CI:  [${p3CI[0].toFixed(3)}%, ${p3CI[1].toFixed(3)}%]`);
console.log(`Delta (P3 - P2) 95% CI: [${deltaCI[0].toFixed(3)} pp, ${deltaCI[1].toFixed(3)} pp]`);
console.log(`Includes Zero: ${deltaCI[0] <= 0 && deltaCI[1] >= 0 ? 'YES' : 'NO'}`);

const bootstrapResults = {
  B,
  p2PointRatePct: Number((p2Rate * 100).toFixed(4)),
  p2CI95Pct: [Number(p2CI[0].toFixed(3)), Number(p2CI[1].toFixed(3))],
  p3PointRatePct: Number((p3Rate * 100).toFixed(4)),
  p3CI95Pct: [Number(p3CI[0].toFixed(3)), Number(p3CI[1].toFixed(3))],
  observedDeltaPP: Number(observedDelta.toFixed(4)),
  deltaCI95PP: [Number(deltaCI[0].toFixed(3)), Number(deltaCI[1].toFixed(3))],
  includesZero: deltaCI[0] <= 0 && deltaCI[1] >= 0
};

fs.writeFileSync(
  'C:/Users/sleyt/sentinel-audit/benchmark/phase3/bootstrap_results.json',
  JSON.stringify(bootstrapResults, null, 2)
);
console.log('Saved bootstrap results to bootstrap_results.json');
