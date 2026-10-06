'use strict';
// Ad-hoc adapter check: drives the real semgrep binary through the v1 adapter
// and prints the normalized finding identities.  Not part of the test suite.
const path = require('path');
const os = require('os');
const fs = require('fs');
const { loadConfig } = require('../lib/core');
const { executeSpecialist } = require('../workflow/specialist-runtime');

const target = process.argv[2] || os.tmpdir();
const { tools, policies } = loadConfig();
const ctx = {
  root: target,
  work: fs.mkdtempSync(path.join(os.tmpdir(), 'adp-smoke-')),
  auditRoot: path.resolve(__dirname, '..'),
  tools,
  policies,
  inv: { mainLanguage: 'javascript' },
  pre: { health: {} },
  toolResolutions: {},
  toolOverrides: null,
  keepDb: false,
  timeoutFor: (tool) => 120000,
};

(async () => {
  const tool = process.argv[3] || 'semgrep';
  const env = await executeSpecialist(tool, target, ctx, { id: 'j1', attempt: 1, signal: new AbortController().signal });
  console.log(`tool        : ${tool}`);
  console.log('status      :', env.status);
  console.log('verdict     :', env.verdict);
  console.log('version     :', env.version);
  console.log('error       :', env.error || '(none)');
  console.log('findings    :', (env.findings || []).length);
  for (const f of (env.findings || []).slice(0, 12)) {
    const rel = f.file ? path.relative(target, f.file) : '<null: outside root or unresolved>';
    console.log(`  ${String(f.rule).padEnd(58)} ${f.level || '-'.padEnd(7)} ${rel}:${f.line}`);
  }
  console.log('work dir    :', ctx.work);
})();
