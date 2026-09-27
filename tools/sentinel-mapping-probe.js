'use strict';
/**
 * Regression probe for the sentinel adapter's field mapping.
 *
 * It asserts the real adapter functions against the vendored engine's actual
 * output shape, using a synthetic fixture. It never touches a target repository
 * and never executes target code.
 *
 * Why it exists: the adapter used to read only `message`/`detail`/`title`, none of
 * which the engine emits, so 100% of Sentinel's evidence was discarded and every
 * observation landed with an empty detail. A copy of the mapping would drift
 * silently, so this imports the shipping functions instead.
 *
 * Run: node tools/sentinel-mapping-probe.js
 */
const path = require('path');
const A = require('../adapters');

const ENGINE = process.env.SENTINEL_ENGINE || 'C:\\Users\\sleyt\\sentinel-purple';
const { ingest } = require(path.join(ENGINE, 'vendor', 'sentinel_x', 'inputAdapter'));
const { extractAll } = require(path.join(ENGINE, 'vendor', 'sentinel_x', 'evidenceFeed'));

let failures = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label.padEnd(58)} got=${got}${ok ? '' : ' want=' + want}`);
};
const checkTrue = (label, cond) => check(label, !!cond, true);

const SOURCE = [
  "import fs from 'node:fs';",
  "const express = require('express');",
  "const ENDPOINT = 'https://api.example.com/v1/collect';",
  "export function run(userInput) {",
  "  fs.writeFileSync('/tmp/' + userInput, 'payload');",
  "  fetch(ENDPOINT, { method: 'POST', body: userInput });",
  "  return eval(userInput);",
  "}",
].join('\n');

const pkg = ingest({ files: [{ name: 'src/fixture.js', content: SOURCE }], id: 'probe' });
const obs = (extractAll(pkg) || {}).observations || [];

console.log('sentinel adapter mapping vs real engine output');
console.log(`  engine emitted ${obs.length} observation(s)\n`);

const mapped = obs.map((o) => {
  const detail = A.sentinelDetail(o);
  return { o, detail, line: A.sentinelLine(o), cls: A.sentinelClass(o, detail, 'src/fixture.js') };
});

for (const m of mapped) {
  console.log(`  ${String(m.o.kind).padEnd(9)} line=${String(m.line).padEnd(4)} ${m.cls.padEnd(18)} ${m.detail}`);
}
console.log('');

checkTrue('engine produced observations', obs.length > 0);
check('no observation loses its detail', mapped.filter((m) => m.detail === '').length, 0);
checkTrue('the legacy mapping would have produced an empty detail', obs.every((o) => !String(o.message || o.detail || o.title || '')));

const byKind = (k) => mapped.filter((m) => m.o.kind === k);
checkTrue('import is observation-only', byKind('import').every((m) => m.cls === 'OBSERVATION_ONLY'));
checkTrue('require is observation-only', byKind('require').every((m) => m.cls === 'OBSERVATION_ONLY'));
checkTrue('string literal is observation-only', byKind('string').every((m) => m.cls === 'OBSERVATION_ONLY'));
check('string literal now exposes its value', (byKind('string')[0] || {}).detail, 'value=https://api.example.com/v1/collect');
check('import now exposes its source', (byKind('import')[0] || {}).detail, 'source=node:fs imports=fs');
checkTrue('require now exposes its resolved target', (byKind('require')[0] || {}).detail.includes('target=express'));

const exec = (byKind('exec')[0] || {}).detail || '';
check('exec is actionable', (byKind('exec')[0] || {}).cls, 'ACTIONABLE_SIGNAL');
checkTrue('exec detail names the api', exec.includes('api=eval'));
checkTrue('exec detail names the sink', exec.includes('sink=eval'));
checkTrue('exec detail names the argument', exec.includes('arg=userInput'));

check('write is actionable', (byKind('write')[0] || {}).cls, 'ACTIONABLE_SIGNAL');
checkTrue('write detail names the api', ((byKind('write')[0] || {}).detail || '').includes('api=fs.writeFileSync'));
checkTrue('write detail carries the tainted arg', ((byKind('write')[0] || {}).detail || '').includes('arg=/tmp/userInput'));

check('download is actionable', (byKind('download')[0] || {}).cls, 'ACTIONABLE_SIGNAL');
checkTrue('download detail names the api', ((byKind('download')[0] || {}).detail || '').includes('api=fetch'));

// An unevidenced behaviour must not escalate, whatever its kind.
check('behaviour with no evidence is observation-only', A.sentinelClass({ kind: 'exec' }, '', 'src/a.js'), 'OBSERVATION_ONLY');
check('behaviour with evidence but no file is observation-only', A.sentinelClass({ kind: 'exec', api: 'eval' }, 'api=eval', null), 'OBSERVATION_ONLY');
check('breadth kind with evidence is still observation-only', A.sentinelClass({ kind: 'import', source: 'fs' }, 'source=fs', 'src/a.js'), 'OBSERVATION_ONLY');
check('a real line is read from line', A.sentinelLine({ line: 42 }), 42);
check('a real line is read from a numeric loc', A.sentinelLine({ loc: 17 }), 17);
check('a string loc is not mistaken for a line', A.sentinelLine({ loc: 'comment' }), null);
check('a rule field is preferred over a cosmetic kind', A.sentinelClass({ kind: 'string', rule: 'SENTINEL_URL_LITERAL' }, 'value=x', 'src/a.js'), 'OBSERVATION_ONLY');

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : failures + ' CHECK(S) FAILED'}`);
process.exit(failures === 0 ? 0 : 1);
