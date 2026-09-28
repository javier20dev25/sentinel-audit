'use strict';
/**
 * Regression probe for Sentinel Cloud signal normalization. This synthetic
 * payload does not load another Sentinel product or touch a target repository.
 * The direct engine integration is covered separately by
 * sentinel-cloud-direct-smoke.js.
 */
const path = require('path');
const { normalizeCloudSignals } = require('../adapters');
const { buildRoutePlan } = require('../workflow/audit');

let failures = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label.padEnd(52)} got=${got}${ok ? '' : ' want=' + want}`);
};
const checkTrue = (label, cond) => check(label, !!cond, true);

const root = path.resolve('C:/sentinel-cloud-mapping-fixture');
const raw = [
  { type: 'SEMANTIC_DYNAMIC_EXECUTION', file: 'src/run.js', line: 3, title: 'Dynamic execution', evidence: 'eval(userInput)' },
  { type: 'IMPORT_OBSERVATION', file: 'src/run.js', line: 1, title: 'Import observed', evidence: 'node:fs' },
  { type: 'SEMANTIC_DYNAMIC_EXECUTION', file: '../outside.js', line: 1, title: 'Outside root', evidence: 'eval(x)' },
];
const mapped = normalizeCloudSignals(root, raw);
const route = buildRoutePlan(mapped);

console.log('Sentinel Cloud normalization and route probe');
check('preserves all raw signal rows', mapped.length, 3);
check('process signal is actionable', mapped[0].signalClass, 'ACTIONABLE_SIGNAL');
check('process signal category is retained', mapped[0].category, 'process');
check('signal evidence is retained', mapped[0].detail, 'Dynamic execution | eval(userInput)');
check('original engine signal is retained', mapped[0].rawEngineSignal, raw[0]);
check('breadth import remains observation-only', mapped[1].signalClass, 'OBSERVATION_ONLY');
check('outside-root location cannot be actionable', mapped[2].signalClass, 'OBSERVATION_ONLY');
check('outside-root location is discarded', mapped[2].file, null);
check('process route opens CodeQL and Semgrep', route.tools.join(','), 'codeql,semgrep');
checkTrue('unrelated SCA tools are not routed', !route.tools.includes('trivy') && !route.tools.includes('osv'));

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
