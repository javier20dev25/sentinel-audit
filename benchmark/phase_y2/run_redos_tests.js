const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('../../sentinel-y');

const tests = [
  {
    name: 'Superlinear regex with ambiguous whitespace repetition (tough-cookie vulnerable)',
    code: `
var COOKIE_PAIR = /^(([^=;]+))\\s*=\\s*([^\\n\\r\\0]*)/;
function parse(str) {
  return str.match(COOKIE_PAIR);
}
`,
    expectedRule: 'Y-REDOS-001',
    expectedVerdict: 'CONFIRMED'
  },
  {
    name: 'Bounded whitespace repetition regex (tough-cookie fixed)',
    code: `
var COOKIE_PAIR = /^(([^=;]+))\\s{0,256}=\\s*([^\\n\\r\\0]*)/;
function parse(str) {
  return str.match(COOKIE_PAIR);
}
`,
    expectedRule: null,
    expectedVerdict: 'CLEAN'
  },
  {
    name: 'Catastrophic backtracking capture in argument escaping (cross-spawn vulnerable)',
    code: `
function escapeArg(arg) {
  return arg.replace(/(\\\\*)"/g, '$1$1\\\\"');
}
`,
    expectedRule: 'Y-REDOS-001',
    expectedVerdict: 'CONFIRMED'
  },
  {
    name: 'Lookahead protected argument escaping (cross-spawn fixed)',
    code: `
function escapeArg(arg) {
  return arg.replace(/(?=\\\\*?)"/g, '$1$1\\\\"');
}
`,
    expectedRule: null,
    expectedVerdict: 'CLEAN'
  },
  {
    name: 'Safe linear regular expression',
    code: `
var SIMPLE_ID = /^[a-zA-Z0-9_-]+$/;
function isValidId(id) {
  return SIMPLE_ID.test(id);
}
`,
    expectedRule: null,
    expectedVerdict: 'CLEAN'
  }
];

const results = tests.map(t => {
  const findings = analyzeFile('test_redos.js', t.code);
  const matched = findings.find(f => f.ruleId === t.expectedRule);
  const pass = t.expectedRule ? (!!matched && matched.verdict === t.expectedVerdict) : findings.length === 0;
  return {
    name: t.name,
    expectedRule: t.expectedRule,
    actualFindings: findings.length,
    pass
  };
});

fs.writeFileSync(path.resolve(__dirname, 'PHASE_Y2_REDOS_TESTS.json'), JSON.stringify({
  suite: 'Sentinel Y - ReDoS Unit Test Suite',
  totalTests: tests.length,
  passed: results.filter(r => r.pass).length,
  results
}, null, 2));

console.log(`ReDoS tests completed: ${results.filter(r => r.pass).length}/${tests.length} passed.`);
