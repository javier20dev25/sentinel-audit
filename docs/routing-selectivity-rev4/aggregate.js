'use strict';
// Agrega los brazos A/B/F y produce los entregables de Rev.4.
//
//  A = escaneo por directorio      -> par justo de TIEMPO (1 proceso por config, igual que B)
//  B = shortlist promovida Cloud   -> brazo routed (produccion, Rev.2)
//  F = todos los archivos, lotes   -> denominador de RECALL (universo completo)
//
// Escribe: routing-selectivity.json, candidate-routing-ledger.json,
//          per-repo/<repo>.json  e imprime la tabla final.

const fs = require('fs');
const path = require('path');

const W = process.env.TEMP + '\\opencode\\cloud-calibration-5';
const AB = path.join(W, 'ab');
const REPOS = ['expressjs__express', 'fastify__fastify', 'sveltejs__svelte', 'vercel__flags', 'vercel__swr'];
const LEVELS = [1.0, 0.95, 0.90];

const rd = (p) => (fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null);

// Normaliza a ruta relativa al repo. A/B devuelven absolutos; F ya devuelve relativos.
function rel(repo, p) {
  if (!p) return null;
  let s = String(p).split('\\').join('/');
  const i = s.indexOf('clones/' + repo + '/');
  if (i >= 0) return s.slice(i + ('clones/' + repo + '/').length);
  const j = s.indexOf(repo + '/');
  if (j >= 0) return s.slice(j + repo.length + 1);
  return s;
}
const key = (f) => rel(REPOCTX, f.path) + '|' + f.line + '|' + f.checkId;
// Semgrep puede reportar el MISMO hallazgo en varios rulesets (medido en svelte:
// detect-child-process y unknown-value-with-script-tag estan en p/security-audit y en
// p/secrets). Sin deduplicar, el numerador y el denominador no son comparables.
const dedupe = (arr) => { const m = new Map(); for (const f of arr) { const k = key(f); if (!m.has(k)) m.set(k, f); } return [...m.values()]; };
let REPOCTX = null;

const pct = (a, b) => (b === 0 ? null : Math.round((a / b) * 1000) / 10);
const perRepo = [];
const allExclusions = [];
const ledger = [];

for (const repo of REPOS) {
  REPOCTX = repo;
  const A = rd(path.join(AB, repo + '__A.json'));
  const B = rd(path.join(AB, repo + '__B.json'));
  const F = rd(path.join(AB, repo + '__F.json'));
  if (!A || !B || !F) { console.log('FALTA un brazo para ' + repo); continue; }
  const exp = rd(path.join(W, 'out', repo, 'expediente.json'));

  const Fd = dedupe(F.findings), Bd = dedupe(B.findings), Ad = dedupe(A.findings);
  const fk = (arr) => new Set(arr.map(key));
  const U = fk(Fd), R = fk(Bd);
  const rec = [...R].filter((k) => U.has(k)).length;
  const lost = Fd.filter((f) => !R.has(key(f)));
  const extra = Bd.filter((f) => !U.has(key(f)));

  // ranking Cloud: nº de señales ACTIONABLE por archivo (campo existente, sin heurística nueva)
  const act = new Map();
  for (const s of (exp.tools.sentinel.findings || [])) {
    if (s.signalClass !== 'ACTIONABLE_SIGNAL') continue;
    const r = rel(repo, s.file); if (!r) continue;
    act.set(r, (act.get(r) || 0) + 1);
  }
  const promoted = (exp.shortlist.files || []).map((f) => rel(repo, f));
  const promotedSet = new Set(promoted);
  const ranked = promoted.slice().sort((x, y) => (act.get(y) || 0) - (act.get(x) || 0) || x.localeCompare(y));
  const uniFiles = F.filesScannedUnion;

  // curva de sensibilidad: K minimo de archivos promovidos para alcanzar cada recall
  const curve = [];
  for (const lvl of LEVELS) {
    const need = lvl * U.size;
    let acc = 0, k = 0;
    for (const f of ranked) {
      acc += Fd.filter((x) => rel(repo, x.path) === f).length;
      k++;
      if (acc >= need) break;
    }
    curve.push({
      targetRecall: lvl, filesNeeded: k, promotedTotal: ranked.length,
      filesPctOfFullUniverse: pct(k, uniFiles),
      findingsCaptured: acc, findingsTotal: U.size,
      achievedRecall: U.size ? Math.round((acc / U.size) * 1000) / 10 : null,
      exact: acc >= need,
      coverageNote: k === ranked.length ? 'requiere la shortlist completa' : 'subconjunto de la shortlist',
    });
  }

  for (const f of lost) {
    allExclusions.push({
      repo, file: rel(repo, f.path), line: f.line, rule: f.checkId, severity: f.severity,
      message: f.message, cloudActionableSignalsInFile: act.get(rel(repo, f.path)) || 0,
      fileInCloudShortlist: promotedSet.has(rel(repo, f.path)),
      reason: promotedSet.has(rel(repo, f.path))
        ? 'archivo promovido pero el finding no reaparece en el brazo routed (no determinista entre corridas)'
        : 'archivo NO promovido por Sentinel Cloud -> perdido por routing',
    });
  }

  perRepo.push({
    repo, commit: F.commit, tree: F.tree, semgrepVersion: F.semgrepVersion,
    configs: F.configs, perFileTimeoutS: F.perFileTimeoutS,
    files: { fullUniverse_F: F.filesScannedUnion, directoryScan_A: A.filesScannedUnion, routed_B: B.filesScannedUnion, promotedByCloud: promoted.length },
    fileReduction: {
      vsFullUniverse_pct: pct(F.filesScannedUnion - B.filesScannedUnion, F.filesScannedUnion),
      vsDirectoryScan_pct: pct(A.filesScannedUnion - B.filesScannedUnion, A.filesScannedUnion),
    },
    findings: {
      fullUniverse_F: U.size, directoryScan_A: Ad.length, routed_B: R.size,
      rawReported_F: F.findings.length, rawReported_B: B.findings.length,
      rawReported_A: A.findings.length,
      duplicateAcrossRulesets_F: F.findings.length - U.size,
      recallOfFullUniverse_pct: pct(rec, U.size), matched: rec,
      lostByRouting: lost.length, inRoutedNotInFull: extra.length,
    },
    time: {
      pairUsed: 'A(directorio) vs B(routed): 1 proceso por config en ambos, misma maquina',
      directoryScan_A_ms: A.wallMsTotal, routed_B_ms: B.wallMsTotal,
      reduction_pct: pct(A.wallMsTotal - B.wallMsTotal, A.wallMsTotal),
      fullUniverse_F_ms_notComparable: F.wallMsTotal, fullUniverse_F_note: 'loteado en ' + F.batches + ' procesos por config; incluye costo de startup repetido',
    },
    cost: {
      peakRssMB: { A: A.usage.peakRssMB, B: B.usage.peakRssMB, F: F.usage.peakRssMB },
      cpuSec: { A: A.usage.cpuSec, B: B.usage.cpuSec, F: F.usage.cpuSec },
    },
    errors: { A: A.errorsTotal, B: B.errorsTotal, F: F.errorsTotal },
    sensitivityCurve: curve,
    gate1_reproducibility: {
      rev2RecordedSemgrepFindings: (exp.tools.semgrep.findings || []).length,
      rev2Rev2CapFiles: 40,
      rev2ShortlistFiles: promoted.length,
      note: 'Rev.2 ejecuto Semgrep sobre la shortlist CAPADA a max-scope-files=40; este brazo B usa la shortlist completa, asi que B != Rev.2 por construccion',
    },
    rejectedDollarPaths_F: (F.rejectedDollarPaths || []).length,
  });

  // ledger de candidatos de Rev.2
  for (const c of (exp.candidates || [])) {
    const cf = rel(repo, c.file);
    const cTools = (c.tools || []).slice();
    const inU = Fd.filter((f) => rel(repo, f.path) === cf && f.line === c.line);
    const inR = Bd.filter((f) => rel(repo, f.path) === cf && f.line === c.line);
    ledger.push({
      repo, candidateId: c.candidateId, file: cf, line: c.line,
      originTools: cTools, semgrepOrigin: cTools.includes('semgrep'), codeqlOrigin: cTools.includes('codeql'),
      disposition: c.disposition, state: c.state,
      cloudFilePromoted: promotedSet.has(cf),
      cloudActionableSignalsInFile: act.get(cf) || 0,
      semgrepFoundInFullUniverse_F: inU.length > 0, semgrepRules_F: inU.map((f) => f.checkId),
      semgrepFoundInRouted_B: inR.length > 0, semgrepRules_B: inR.map((f) => f.checkId),
      measurableBySemgrep: cTools.includes('semgrep'),
      missClassification: cTools.includes('semgrep')
        ? (inR.length ? 'RECOVERED' : 'LOST_BY_ROUTING')
        : 'NOT_MEASURABLE_BY_SEMGREP (CodeQL es repo-level; su scope no lo define la shortlist)',
    });
  }
}

const tot = (fn) => perRepo.reduce((a, r) => a + fn(r), 0);
const agg = {
  files: { fullUniverse_F: tot((r) => r.files.fullUniverse_F), directoryScan_A: tot((r) => r.files.directoryScan_A), routed_B: tot((r) => r.files.routed_B), promotedByCloud: tot((r) => r.files.promotedByCloud) },
  findings: { fullUniverse_F: tot((r) => r.findings.fullUniverse_F), directoryScan_A: tot((r) => r.findings.directoryScan_A), routed_B: tot((r) => r.findings.routed_B), matched: tot((r) => r.findings.matched), lostByRouting: tot((r) => r.findings.lostByRouting) },
};
agg.findings.recallOfFullUniverse_pct = pct(agg.findings.matched, agg.findings.fullUniverse_F);
agg.fileReduction_vsFullUniverse_pct = pct(agg.files.fullUniverse_F - agg.files.routed_B, agg.files.fullUniverse_F);
agg.time_directoryScan_A_ms = tot((r) => r.time.directoryScan_A_ms);
agg.time_routed_B_ms = tot((r) => r.time.routed_B_ms);
agg.time_reduction_pct = pct(agg.time_directoryScan_A_ms - agg.time_routed_B_ms, agg.time_directoryScan_A_ms);

const rev2SemgrepMeasurable = ledger.filter((c) => c.measurableBySemgrep);
const out = {
  experiment: 'Rev.4 routing selectivity',
  generatedAt: new Date().toISOString(),
  source: 'Rev.2 artifacts recovered at ' + W + '; no Sentinel Cloud scan was re-run',
  design: {
    A: 'escaneo por DIRECTORIO del repo (mecanismo unscoped de adapters/index.js:189). Par de tiempo justo: 1 proceso por config, igual que B.',
    B: 'solo la shortlist promovida por Sentinel Cloud, sin tope de archivos (Rev.2 si uso max-scope-files=40). Brazo routed.',
    F: 'lista explicita de TODOS los archivos versionados, en lotes de 300 rutas relativas. Unico brazo con universo conocido y completo; denominador de recall.',
    variableUnica: 'el conjunto de targets. Mismo repo, commit, version de Semgrep (1.175.0), reglas (p/security-audit, p/secrets) y flags en los tres brazos.',
  },
  caveats: [
    'El recorrido por directorio de Semgrep salta test/ y build/ (medido: 0 de 93 archivos de test/ en fastify, 0 de 19 en express). Por eso A no es superconjunto de B y A NO sirve como denominador de recall; de ahi el brazo F.',
    'Semgrep aborta el lote entero (exit 2, "Invalid scanning root") si una ruta contiene $. 64 archivos de svelte quedaron fuera de F y se registran como rejectedDollarPaths. Ninguno estaba en la shortlist de Rev.2.',
    'Semgrep es un detector monorepo-independent por archivo: el recall de findings se calcula sobre archivos y lineas exactos, no sobre regiones.',
    'Los hallazgos se deduplican por ruta+linea+regla. Semgrep reporta el mismo hallazgo una vez por cada ruleset que lo contiene, asi que el conteo raw puede superar al real (svelte: 11 raw -> 7 unicos).',
    'A y B usan 1 proceso por config; F usa 62/12/6 procesos segun repo. El wall time de F no es comparable y no se usa para ninguna conclusion de ahorro.',
  ],
  aggregate: agg,
  perRepo,
  totals: { semgrepMeasurableCandidates: rev2SemgrepMeasurable.length, ledgerRows: ledger.length },
};
fs.writeFileSync(path.join(AB, 'routing-selectivity.json'), JSON.stringify(out, null, 2));
fs.writeFileSync(path.join(AB, 'candidate-routing-ledger.json'), JSON.stringify({ generatedAt: out.generatedAt, note: 'Semgrep solo puede medir los candidatos de origen semgrep; los de CodeQL son repo-level y su scope no lo define la shortlist', rows: ledger }, null, 2));
const prDir = path.join(AB, 'per-repo'); if (!fs.existsSync(prDir)) fs.mkdirSync(prDir, { recursive: true });
for (const r of perRepo) fs.writeFileSync(path.join(prDir, r.repo + '.json'), JSON.stringify(r, null, 2));
fs.writeFileSync(path.join(AB, 'false-exclusion-ledger.json'), JSON.stringify({ generatedAt: out.generatedAt, count: allExclusions.length, rows: allExclusions }, null, 2));

console.log('\n=== TABLA FINAL (findings = Semgrep, F = universo completo) ===');
console.log('repo'.padEnd(20) + 'F files'.padStart(8) + 'B files'.padStart(8) + 'red%'.padStart(6) + 'F find'.padStart(8) + 'B find'.padStart(8) + 'recall%'.padStart(8) + 'A ms'.padStart(8) + 'B ms'.padStart(8) + 'time%'.padStart(7));
for (const r of perRepo) console.log(
  r.repo.padEnd(20) + String(r.files.fullUniverse_F).padStart(8) + String(r.files.routed_B).padStart(8) +
  String(r.fileReduction.vsFullUniverse_pct).padStart(6) + String(r.findings.fullUniverse_F).padStart(8) +
  String(r.findings.routed_B).padStart(8) + String(r.findings.recallOfFullUniverse_pct).padStart(8) +
  String(r.time.directoryScan_A_ms).padStart(8) + String(r.time.routed_B_ms).padStart(8) + String(r.time.reduction_pct).padStart(7));
console.log('TOTAL'.padEnd(20) + String(agg.files.fullUniverse_F).padStart(8) + String(agg.files.routed_B).padStart(8) +
  String(agg.fileReduction_vsFullUniverse_pct).padStart(6) + String(agg.findings.fullUniverse_F).padStart(8) +
  String(agg.findings.routed_B).padStart(8) + String(agg.findings.recallOfFullUniverse_pct).padStart(8) +
  String(agg.time_directoryScan_A_ms).padStart(8) + String(agg.time_routed_B_ms).padStart(8) + String(agg.time_reduction_pct).padStart(7));

console.log('\n=== CURVA DE SENSIBILIDAD (archivos promovidos para alcanzar cada recall) ===');
for (const r of perRepo) {
  console.log('  ' + r.repo);
  for (const c of r.sensitivityCurve) console.log('    objetivo ' + (c.targetRecall * 100) + '%  archivos=' + c.filesNeeded + '/' + r.files.promotedByCloud +
    '  (' + c.filesPctOfFullUniverse + '% del universo)  capturado=' + c.findingsCaptured + '/' + c.findingsTotal +
    '  real=' + c.achievedRecall + '%' + (c.exact ? '' : '  (no alcanza el objetivo)'));
}

console.log('\n=== EXCLUSIONES FALSAS (hallazgos del universo que el routing pierde) ===');
if (!allExclusions.length) console.log('  ninguna');
for (const e of allExclusions) console.log('  ' + e.repo + '  ' + e.file + ':' + e.line + '  ' + e.rule + '  senalAccionableEnArchivo=' + e.cloudActionableSignalsInFile + '  (' + e.reason + ')');

console.log('\n=== LEDGER DE CANDIDATOS Rev.2 ===');
console.log('  total=' + ledger.length + '  medibles por Semgrep=' + rev2SemgrepMeasurable.length);
for (const c of ledger) if (c.measurableBySemgrep) console.log('  ' + c.repo + ' ' + c.candidateId + ' ' + c.file + ':' + c.line + '  F=' + c.semgrepFoundInFullUniverse_F + ' B=' + c.semgrepFoundInRouted_B + '  ' + c.missClassification);
console.log('\n  por clase: ' + JSON.stringify(ledger.reduce((a, c) => { a[c.missClassification.split(' ')[0]] = (a[c.missClassification.split(' ')[0]] || 0) + 1; return a; }, {})));
