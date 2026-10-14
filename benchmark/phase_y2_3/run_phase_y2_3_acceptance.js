'use strict';

/**
 * Phase Y2.3 Acceptance Harness — Sentinel Y v0.3
 *
 * Runs the acceptance suite for the v0.3 candidate:
 *   1. Counterexamples CE-01..CE-05 (classification precision)
 *   2. Calibration regressions (deep-extend, mixin-deep, tough-cookie,
 *      cross-spawn) + json5 as a diagnostic regression
 *   3. Benign negative controls
 *   4. Unknown / unsupported inputs
 *
 * Writes PHASE_Y2_3_RESULTS.jsonl and PHASE_Y2_3_METRICS.json.
 * Does not mutate frozen engines (v0.1, v0.2) or historical evidence.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const engine = require('../../sentinel-y/v0.3');
const ENGINE_VERSION = engine.version;
const CLONES = path.resolve(__dirname, '..', 'phase5', 'clones');

function readPinned(cloneDir, sha, file) {
  return execFileSync('git', ['-C', path.join(CLONES, cloneDir), 'show', `${sha}:${file}`], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
}

// --- Counterexamples CE-01..CE-05 -----------------------------------------

const counterexamples = [
  {
    id: 'CE-01',
    family: 'PROTOTYPE_POLLUTION',
    name: 'reassign_proto_with_null',
    code: 'function reassignProto(target, key) { for (let key in obj) { target[key] = null; } }',
    ruleId: 'Y-PROTO-001',
    // Must fire, but must NOT auto-confirm Object.prototype contamination
    // from a null write whose data flow is not proven.
    expectFired: true,
    forbidConfirmed: true,
  },
  {
    id: 'CE-02',
    family: 'PROTOTYPE_POLLUTION',
    name: 'class_prototype_dynamic_method_injection',
    code: 'for (let m in userMethods) { Service.prototype[m] = function() { return userMethods[m]; }; }',
    ruleId: 'Y-PROTO-001',
    // v0.2 suppressed this as CLEAN; v0.3 must emit a finding (uncertainty).
    expectFired: true,
    forbidConfirmed: true,
  },
  {
    id: 'CE-03',
    family: 'PROTOTYPE_POLLUTION',
    name: 'nested_property_write_with_primitive_boolean_leaf',
    code: 'for (let p in path) { obj[p] = true; }',
    ruleId: 'Y-PROTO-001',
    // Must not confirm prototype arrival without evidence of the path.
    expectFired: true,
    forbidConfirmed: true,
  },
  {
    id: 'CE-04',
    family: 'REDOS',
    name: 'finite_quantifier_nested_under_star',
    code: 'var r = /(a{0,256})*/;',
    ruleId: 'Y-REDOS-001',
    // Bounded inner quantifier must not suppress the outer unbounded ambiguity.
    expectFired: true,
    forbidConfirmed: false,
  },
  {
    id: 'CE-05',
    family: 'REDOS',
    name: 'lookahead_assertion_without_following_isolation',
    code: 'var r = /(?=a+)(a+)+/;',
    ruleId: 'Y-REDOS-001',
    // Lookahead presence must not suppress the trailing ambiguous group.
    expectFired: true,
    forbidConfirmed: false,
  },
];

// --- Calibration regressions (pinned vulnerable revisions) -----------------

const regressions = [
  {
    id: 'REG-deep-extend',
    package: 'deep-extend',
    file: 'lib/deep-extend.js',
    ruleId: 'Y-PROTO-001',
    read: () => readPinned('unclechu_node-deep-extend', '9653940a75c2ef2b1a503b24cbadd707cccffa8c', 'lib/deep-extend.js'),
  },
  {
    id: 'REG-mixin-deep',
    package: 'mixin-deep',
    file: 'index.js',
    ruleId: 'Y-PROTO-001',
    read: () => readPinned('jonschlinkert_mixin-deep', '9925af763440a50891358d00db0e6a5accc50ee6', 'index.js'),
  },
  {
    id: 'REG-json5',
    package: 'json5',
    file: 'src/parse.js',
    ruleId: 'Y-PROTO-001',
    read: () => readPinned('json5_json5', '072eb402fc107a2f568ba78962d3d99de95032a9', 'src/parse.js'),
  },
  {
    id: 'REG-tough-cookie',
    package: 'tough-cookie',
    file: 'lib/cookie.js',
    ruleId: 'Y-REDOS-001',
    read: () => readPinned('salesforce_tough-cookie', 'fcc8abfa3d3cab4f99da38f3f3749b1b186eb5a4', 'lib/cookie.js'),
  },
  {
    id: 'REG-cross-spawn',
    package: 'cross-spawn',
    file: 'lib/util/escape.js',
    ruleId: 'Y-REDOS-001',
    read: () => readPinned('moxystudio_node-cross-spawn', '9521e2da94d94998f948e0455903e62d87884600', 'lib/util/escape.js'),
  },
];

// --- Benign negative controls ---------------------------------------------

const benignControls = [
  { id: 'BEN-shallow-copy', note: 'shallow property copy on plain dictionary', code: 'function copy(dst, src){ for (const k in src){ dst[k] = src[k]; } }' },
  { id: 'BEN-null-proto', note: 'null-prototype object map', code: 'const o = Object.create(null); for (const k in src){ o[k] = src[k]; }' },
  { id: 'BEN-regex-anchored', note: 'anchored linear regex', code: 'var re = /^[a-z]+$/;' },
  { id: 'BEN-regex-bounded', note: 'bounded quantifier without nesting', code: 'var re = /\\d{1,4}/;' },
  { id: 'BEN-guarded-merge', note: 'full prototype guard', code: "function m(t, s){ for (var key in s){ if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue; t[key] = s[key]; } }" },
];

// --- Unknown / unsupported ------------------------------------------------

const unknownCases = [
  { id: 'UNK-comment-only', code: '// nothing to analyse' },
  { id: 'UNK-empty', code: '' },
  { id: 'UNK-partial-syntax', code: 'function ( { for (let x in' },
];

function findRule(findings, ruleId) {
  return findings.filter((f) => f.ruleId === ruleId);
}

const resultRows = [];
let cePass = 0;
let regPass = 0;
let regConfirmed = 0;
let regCandidateOnly = 0;
let benignPass = 0;
let unknownPass = 0;
let determinismPass = 0;

// 1. Counterexamples
for (const ce of counterexamples) {
  const findings = engine.analyzeFile(`${ce.name}.js`, ce.code);
  const ruleFindings = findRule(findings, ce.ruleId);
  const fired = ruleFindings.length > 0;
  const hasConfirmed = ruleFindings.some((f) => f.verdict === 'CONFIRMED');
  const verdicts = [...new Set(ruleFindings.map((f) => f.verdict))];
  const pass =
    (ce.expectFired ? fired : !fired) &&
    (!ce.forbidConfirmed || !hasConfirmed);
  if (pass) cePass += 1;
  resultRows.push({
    block: 'counterexample',
    id: ce.id,
    family: ce.family,
    ruleId: ce.ruleId,
    fired,
    verdicts,
    confidence: [...new Set(ruleFindings.map((f) => f.confidence))],
    forbidConfirmed: ce.forbidConfirmed,
    hasConfirmed,
    pass,
  });
}

// 2. Regressions
for (const reg of regressions) {
  let code = '';
  let readError = null;
  try {
    code = reg.read();
  } catch (err) {
    readError = err.message;
  }
  const findings = readError ? [] : engine.analyzeFile(reg.file, code);
  const ruleFindings = findRule(findings, reg.ruleId);
  const fired = ruleFindings.length > 0;
  const confirmed = ruleFindings.some((f) => f.verdict === 'CONFIRMED');
  const candidateOnly = fired && !confirmed;
  // A calibration regression is only satisfied by a CONFIRMED detection.
  // Diagnostic cases record whether they fired, without a confirmation bar.
  const pass = !readError && (reg.diagnostic ? fired : confirmed);
  if (pass) regPass += 1;
  if (confirmed) regConfirmed += 1; else if (candidateOnly) regCandidateOnly += 1;
  resultRows.push({
    block: 'regression',
    id: reg.id,
    package: reg.package,
    file: reg.file,
    ruleId: reg.ruleId,
    findingCount: ruleFindings.length,
    confirmed,
    candidateOnly,
    verdicts: [...new Set(ruleFindings.map((f) => f.verdict))],
    diagnostic: !!reg.diagnostic,
    readError,
    pass,
  });
}

// 3. Benign controls — must not raise a CONFIRMED verdict (uncertainty allowed)
for (const ctl of benignControls) {
  const findings = engine.analyzeFile(`${ctl.id}.js`, ctl.code);
  const confirmed = findings.filter((f) => f.verdict === 'CONFIRMED');
  const pass = confirmed.length === 0;
  if (pass) benignPass += 1;
  resultRows.push({
    block: 'benign_control',
    id: ctl.id,
    note: ctl.note,
    findingCount: findings.length,
    confirmedCount: confirmed.length,
    verdicts: [...new Set(findings.map((f) => f.verdict))],
    pass,
  });
}

// 4. Unknown / unsupported — must not crash and must not confirm
for (const unk of unknownCases) {
  let findings = [];
  let crashed = false;
  try {
    findings = engine.analyzeFile(`${unk.id}.js`, unk.code);
  } catch (_e) {
    crashed = true;
  }
  const confirmed = findings.filter((f) => f.verdict === 'CONFIRMED');
  const pass = !crashed && confirmed.length === 0;
  if (pass) unknownPass += 1;
  resultRows.push({
    block: 'unknown',
    id: unk.id,
    crashed,
    findingCount: findings.length,
    confirmedCount: confirmed.length,
    pass,
  });
}

// 5. Determinism — run the whole CE block twice and compare
{
  const first = counterexamples.map((ce) => JSON.stringify(engine.analyzeFile(`${ce.name}.js`, ce.code)));
  const second = counterexamples.map((ce) => JSON.stringify(engine.analyzeFile(`${ce.name}.js`, ce.code)));
  const stable = first.every((v, i) => v === second[i]);
  if (stable) determinismPass += 1;
  resultRows.push({
    block: 'determinism',
    id: 'DET-ce-repeat',
    runsCompared: 2,
    stable,
    pass: stable,
  });
}

const metrics = {
  phase: 'Y2.3',
  engine: 'sentinel-y',
  engineVersion: ENGINE_VERSION,
  frozen: { v0_1: '175004F5AE9E110929D445B27AC9FF40A6AE0EB7B2C8F04CEBDFD6F520905A28', v0_2: 'AC9BECBE913B2114120EF5A33D889A869C25B583252836E7D3C0EEC7597B83C8' },
  generatedAt: new Date().toISOString(),
  blocks: {
    counterexamples: { passed: cePass, total: counterexamples.length },
    regressions: {
      passed: regPass,
      total: regressions.length,
      confirmed: regConfirmed,
      candidateOnly: regCandidateOnly,
    },
    benign_controls: { passed: benignPass, total: benignControls.length },
    unknown: { passed: unknownPass, total: unknownCases.length },
    determinism: { passed: determinismPass, total: 1 },
  },
  note: 'A regression pass does not demonstrate generalisation. Metrics are not merged across blocks.',
};

fs.writeFileSync(path.join(__dirname, 'PHASE_Y2_3_RESULTS.jsonl'), resultRows.map((r) => JSON.stringify(r)).join('\n') + '\n');
fs.writeFileSync(path.join(__dirname, 'PHASE_Y2_3_METRICS.json'), JSON.stringify(metrics, null, 2) + '\n');

console.log(JSON.stringify(metrics.blocks, null, 2));
