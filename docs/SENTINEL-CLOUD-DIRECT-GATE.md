# Sentinel Cloud direct-engine gate

**Campaign gate: CONDITIONAL PASS.** Local engine, raw evidence, local-only
execution, Purple exclusion, and signal routing pass. Production parity is
`UNKNOWN`; any campaign report must carry `Sentinel Cloud local engine;
production parity unverified`. This gate does not start a batch.

## Engine and lineage

| Item | Observed value |
|---|---|
| Local source repository | `C:\Users\sleyt\sentinel-cloud` |
| Local HEAD | `e9e3036026b12862e91f0fb48ad3a482787e8507` |
| Worker entrypoint | `packages/worker/index.js` |
| Worker bridge | `packages/worker/scan-bridge.cjs` |
| Direct engine entrypoint | `packages/worker/core/scanner/index.js` |
| Engine call | `scanDirectory(root, null, 5, { mode: 'local', profile: 'DEFAULT' })` |
| Production lineage | worker imports bridge; bridge requires the direct scanner module |
| Version | Scanner does not publish an independent semver; identify by local HEAD + hashes |
| Hosted source upload | None; the configured test invokes the local module |
| Exact deployed image/source digest | **UNKNOWN — production parity not proven** |

### Production parity investigation (2026-09-27, America/Managua)

The local topology record identifies the worker as Render service
`sentinel-worker` (`srv-danevsf40ujc73bnlgbg`) at
`https://sentinel-worker-8h9t.onrender.com`. A read-only `GET /health` timed
out; it returned no build identity. No Render credential or Render CLI was
available in this process, so Render's deployment API could not be queried.

The GitHub Actions workflow intended to trigger a Render deploy is
[`deploy-worker.yml`](https://github.com/javier20dev25/sentinel-cloud/blob/main/.github/workflows/deploy-worker.yml).
The latest worker-deploy workflow record visible through GitHub was a failed
legacy Railway job on 2026-09-12 at
[`7fdedf546d31c8557af477f5518b9686949323c2`](https://github.com/javier20dev25/sentinel-cloud/actions/runs/34720089557).
It is not proof of the current Render worker state.
GitHub's deployment records for the `Production – sentinel` and
`Production – sentinel-cloud-v2` environments are Vercel web-app deployments,
not evidence for the Render worker. They therefore cannot establish worker
parity. The later local worker checkout at `e9e303...` is not proven deployed.

**Decision:** `PRODUCTION_PARITY = UNKNOWN` (not PASS and not FAIL). The worker
identity remains unknown; no deployment SHA is inferred from local source
lineage, a web-app deploy, or an unavailable health response.

SHA-256 for the inspected Cloud checkout:

| Critical module | SHA-256 |
|---|---|
| `packages/worker/core/scanner/index.js` | `A88A67B73347A53409F8A0FBD241B8009223A181DD0F66D27EC17A5E50CA39D2` |
| `packages/worker/core/scanner/ast_inspector.js` | `4A653487B62F560F9D52717659076EC97BCEA2091CC350BD61F324002BB6A376` |
| `packages/worker/core/scanner/config.js` | `BFDBFFBC6148D9D67D789A7469BBC7DB0D2D04B4DEBC0624FE6D98D4B6289FEF` |

Preflight computes current HEAD, hashes, production-trace checks, and relevant
worker/scanner worktree status each run; use those run-time values if they
differ from the inspection snapshot above.

## Controlled direct smoke

Command (Windows PowerShell; runtime guard required by local policy):

```powershell
$env:NODE_OPTIONS='--require=C:/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js'
node tools/sentinel-cloud-direct-smoke.js
```

The smoke writes inert JS canaries as text in temporary directories. It never
executes or imports those fixtures and invokes no secondary scanner. It tests
both the direct `scanFile` API and the worker's `scanDirectory` API. During the
engine call it replaces Node's HTTP/HTTPS request and low-level socket APIs
(plus `fetch`) with deny stubs and fails if any outbound-network attempt occurs.
This covers the scan path exercised by the smoke; it is not a general proof that
every Cloud engine feature is network-free. It calls the configured engine
through the audit adapter, persists raw results under
`out/sentinel-cloud-direct-gate/`, verifies the `eval` signal routes only CodeQL
+ Semgrep, compares `child_process.exec` forms, and asserts that no Purple module
entered the process. Its machine-readable record is
`out/sentinel-cloud-direct-gate/smoke-summary.json`.

Observed result on **2026-09-27 (America/Managua)**: direct Cloud smoke **PASS**.
The eval canary emitted `CAPABILITY_CHAIN` and `SEMANTIC_DYNAMIC_EXECUTION`;
the routed plan was CodeQL + Semgrep only. The exact call-only exec fixture
emitted `CAPABILITY_CHAIN` through both `scanFile` and `scanDirectory`; the
bound and existing-fixture forms emitted it through `scanDirectory`. See the
focused conclusion below. The record identifies local engine
`e9e3036026b12862e91f0fb48ad3a482787e8507` and its scanner SHA-256. No outbound
network attempt occurred. Individual raw files and the complete machine record
are preserved beneath `out/sentinel-cloud-direct-gate/`.

Machine-record `generatedAt` values are UTC. For example,
`2026-09-28T02:28:29Z` is still 2026-09-27 in America/Managua; the human-facing
observation date above uses the local timezone.

Observed coverage label: `ENGINE_COVERAGE_UNMEASURED`; `filesScanned=1` is
retained only as the engine-reported scan count, never as parsed coverage. This
local smoke does not prove recall across languages or parity with the deployed
production image.

## Gate decisions

| Check | Result | Evidence / limitation |
|---|---|---|
| Correct local Cloud worker source configured | PASS | `config/tools.json`; local HEAD and critical hashes above |
| Production call chain points at same scanner module | PASS (source inspection) | `worker/index.js` → bridge → scanner |
| Direct local module call; no hosted API/network on smoke path | PASS | `mode: local`; direct `require(enginePath)`; HTTP/HTTPS/socket/fetch denied during smoke with zero attempts |
| Sentinel Purple excluded from active config/exports/routes | PASS | No Purple config or exported adapter; smoke loaded no Purple module |
| Raw engine output preserved | PASS | `out/sentinel-cloud-direct-gate/sentinel.json`; smoke asserts it exists |
| Parsed-file coverage / parser errors measured | LIMITATION | Engine does not expose the counters; reports `ENGINE_COVERAGE_UNMEASURED`; no instrumentation was added |
| Signal-first routing demonstrated | PASS | Static `eval` canary routed to CodeQL + Semgrep only |
| Exact deployed worker matches local checkout | UNKNOWN | Render API unavailable; GitHub deploy records found are for Vercel web app |
| Result labeling for parity | PASS | Adapter and expediente label local-engine results with production parity `UNKNOWN` |
| Resume mass campaign | **CONDITIONAL PASS** | Allowed only with explicit local-engine / parity-unverified labels; no batch run performed |

Do not interpret zero Sentinel signals as a clean result. Do not infer
production behavior from this local engine. A batch may use the conditional
gate only if the `UNKNOWN` parity label is accepted and kept on every result;
coverage remains a limitation, not a reason to invent parser metrics or build a
coverage framework now.

## `child_process.exec(userInput)` result

The earlier reported zero was **not reproduced** against the current direct
local engine. On 2026-09-27, the controlled exact call-only fixture produced a
`CAPABILITY_CHAIN` from both `scanFile` and `scanDirectory`; adding an explicit
`require('child_process')` binding also produced `CAPABILITY_CHAIN`. The
Cloud-owned `test_scanner.js` taint fixture form (with `eval(req.body.cmd)` and
`child_process.exec("git clone " + req.query)`) likewise emitted a capability
chain. No fixture code was executed.

This classifies the prior zero as **not reproducible / fixture-or-invocation
dependent**, not as a confirmed engine defect or confirmed regression. The raw
signals are coarse capability evidence (`ARBITRARY_EXEC → EXECUTION`, with
`_evidenceGraphConfirmed: false`); they are useful to route investigation but
do not prove that untrusted input reaches the sink or that a vulnerability
exists. No engine code was changed. See the `childProcessExecUnbound`,
`childProcessExecWithRequire`, `existingCloudTaintFixture`, and `scanFile*`
entries in `smoke-summary.json`.
