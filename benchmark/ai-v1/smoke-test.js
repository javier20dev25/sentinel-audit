'use strict';
const { CASES } = require('./cases');
const { GROUND_TRUTH } = require('./ground-truth');
const { SYSTEM_PROMPT_HASHES, buildTaskPrompt } = require('./prompts');
const { parseResponse, scoreRun } = require('./parser');

console.log('Cases loaded:', CASES.length);
console.log('Ground truth keys:', Object.keys(GROUND_TRUTH).length);
console.log('System prompt hashes:', JSON.stringify(SYSTEM_PROMPT_HASHES, null, 2));
const c = CASES[0];
const prompt = buildTaskPrompt(c, 'AI_ALONE');
console.log('Sample AI_ALONE prompt length (chars):', prompt.length);
console.log('Sample AI_ALONE prompt (first 400):');
console.log(prompt.slice(0, 400));

const sampleResponse = [
  'FINDING: Exfiltration C2 beacon',
  'FILE: scripts/health-check.js',
  'LINE: 6',
  'VERDICT: CONFIRMED',
  'SEVERITY: CRITICAL',
  'REASON: Sends hostname/env to telemetry-analytics.xyz C2 domain.',
  '',
  'SUMMARY:',
  'CONFIRMED: 1',
  'FALSE_POSITIVE: 0',
  'UNKNOWN: 0',
  'OVERALL_VERDICT: CONFIRMED',
].join('\n');

const parsed = parseResponse(sampleResponse, 'AI_ALONE');
const score = scoreRun(parsed, 'MALICIOUS');
console.log('\nParser test (verdict/score):');
console.log('overallVerdict:', parsed.overallVerdict);
console.log('confirmed:', parsed.confirmed);
console.log('score:', score);
console.log('\nSmoke test PASS');
