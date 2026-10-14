const fs = require('fs');
const path = require('path');
const { analyzeFile } = require('../../sentinel-y');

const tests = [
  {
    name: 'Vulnerable recursive assignment without guard',
    code: `
function merge(target, source) {
  for (var key in source) {
    target[key] = source[key];
  }
}
`,
    expectedRule: 'Y-PROTO-001',
    expectedVerdict: 'CONFIRMED'
  },
  {
    name: 'Safe recursive assignment with dominant __proto__ and constructor guard',
    code: `
function merge(target, source) {
  for (var key in source) {
    if (key === '__proto__' || key === 'constructor') continue;
    target[key] = source[key];
  }
}
`,
    expectedRule: null,
    expectedVerdict: 'CLEAN'
  },
  {
    name: 'Safe assignment with isValidKey helper guard',
    code: `
function merge(target, source) {
  for (var key in source) {
    if (!isValidKey(key)) continue;
    target[key] = source[key];
  }
}
`,
    expectedRule: null,
    expectedVerdict: 'CLEAN'
  },
  {
    name: 'Unrelated property write',
    code: `
function updateConfig(obj) {
  obj.version = "1.0.0";
  obj.active = true;
}
`,
    expectedRule: null,
    expectedVerdict: 'CLEAN'
  }
];

const results = tests.map(t => {
  const findings = analyzeFile('test_proto.js', t.code);
  const matched = findings.find(f => f.ruleId === t.expectedRule);
  const pass = t.expectedRule ? (!!matched && matched.verdict === t.expectedVerdict) : findings.length === 0;
  return {
    name: t.name,
    expectedRule: t.expectedRule,
    actualFindings: findings.length,
    pass
  };
});

fs.writeFileSync(path.resolve(__dirname, 'PHASE_Y2_PROTO_TESTS.json'), JSON.stringify({
  suite: 'Sentinel Y - Prototype Pollution Unit Test Suite',
  totalTests: tests.length,
  passed: results.filter(r => r.pass).length,
  results
}, null, 2));

console.log(`Proto tests completed: ${results.filter(r => r.pass).length}/${tests.length} passed.`);
