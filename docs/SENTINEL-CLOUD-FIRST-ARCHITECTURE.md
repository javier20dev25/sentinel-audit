# Sentinel Cloud-first local audit architecture

## Purpose and terminology

This repository is a local audit runner. OpenCode is the local SOC/SISO
orchestrator: the coding agent that reviews, classifies, routes, correlates, and
prepares local case material. It is not another scanner and it does not make
automatic vulnerability or disclosure decisions.

The primary sensor is the **Sentinel Cloud worker scanner source run locally**.
“Cloud” names the production product/engine lineage; this test environment
invokes the worker scanner module in `mode: local` and sends no target source to
the hosted Sentinel service. The direct-engine smoke denies HTTP/HTTPS, socket,
and `fetch` APIs during the exercised scan call and fails if any are attempted.
This evidence applies to that scan path, not every Cloud feature: other worker
or CLI helpers include network-capable npm, OSV, and opt-in telemetry modules
that are not invoked by the local scan call.

```text
local repository
  → Sentinel Cloud worker scanner (direct local module call)
  → preserved raw engine output
  → normalized Sentinel signals
  → deterministic signal-first route plan
  → only justified specialist tools
  → evidence correlation and local human adjudication
  → local case / patch / disclosure drafts (never sent automatically)
```

Sentinel CLI is an interface/integration, not the engine identity. Sentinel
Oracle is a separate function. Sentinel Purple is an archived experiment and
is not configured, imported, or called by this pipeline. A Purple vendored copy
is never an acceptable substitute for the Cloud worker engine.

## Direct engine identity

The runner configuration in `config/tools.json` points to the local checkout
`%USERPROFILE%\sentinel-cloud`, specifically:

* Worker entry: `packages/worker/index.js`
* Production scan bridge: `packages/worker/scan-bridge.cjs`
* Direct scanner module: `packages/worker/core/scanner/index.js`
* Critical AST/config modules: `packages/worker/core/scanner/ast_inspector.js`,
  `packages/worker/core/scanner/config.js`

Production worker lineage is `worker/index.js` → `scan-bridge.cjs` →
`core/scanner/index.js`. The runner requires that same scanner module and calls
`scanDirectory(root, null, 5, { mode: 'local', profile: 'DEFAULT' })`.
Preflight records the local git HEAD and SHA-256 hashes. The currently inspected
checkout is documented with its exact identity in
[`SENTINEL-CLOUD-DIRECT-GATE.md`](SENTINEL-CLOUD-DIRECT-GATE.md).

This demonstrates local source lineage only. The exact source/image digest
currently deployed in Sentinel Cloud production must be independently matched
before claiming byte-for-byte production parity.

## Three-stage local SOC workflow

**Etapa A — Sentinel Cloud sensor.** OpenCode calls the configured local Cloud
worker engine first, stores its raw result, normalizes signals, and emits a
deterministic route plan. No hosted scan API is called.

**Etapa B — selective amplification.** Only signal categories justify
specialists. OpenCode selects the smallest relevant tool set; no actionable
signal means `NO_ACTIONABLE_SENTINEL_FINDINGS` and no secondary tools. Secondary
results verify, contradict, or contextualize the lead; they do not become a
finding-count scorecard.

**Etapa C — SOC correlation and adjudication.** OpenCode correlates overlapping
evidence into cases, tracks unresolved questions and recommended next steps,
and prepares local-only patch/disclosure drafts. A human adjudicates. Nothing is
sent, published, pushed, or opened externally automatically.

## Signal-first routing

Only normalized Sentinel Cloud signals with a supported category, an in-root
file, and useful evidence are `ACTIONABLE_SIGNAL`. Other engine output remains
an observation. A signal is never a vulnerability verdict.

| Sentinel signal | Local route |
|---|---|
| Process/command execution, network, filesystem write | CodeQL + Semgrep; add Bandit for promoted Python files or ShellCheck for shell files |
| Secret/credential | Semgrep secret verification |
| Dependency/SCA | Trivy + OSV |
| Package lifecycle/install behavior | Semgrep + Trivy |
| Obfuscation or unclassified observation alone | Observe; do not start heavyweight tools |
| No actionable signal | `NO_ACTIONABLE_SENTINEL_FINDINGS`; run no secondary tools |

Routing is deterministic and recorded in `expediente.signalRouting`. Secondary
tools amplify or verify a Sentinel-led investigation; their raw finding count
is not a quality metric. Explicit operator overrides, if used, must remain
visible in the run record.

Signals in tests, examples, fixtures, generated, or vendored paths are lowered
or excluded according to the path policy and remain auditable as scope data.

## Evidence, correlation, and adjudication

The raw Cloud result is persisted as `sentinel.json` before normalization. The
normalized record retains its raw engine signal. The shortlist records the
actual promoted file paths, not merely a count. Correlation groups overlapping
tool evidence into one local case rather than treating each tool row as a
separate issue.

The workflow distinguishes a signal, candidate, plausible issue, confirmed
issue, resolved-no-issue disposition, and unresolved case. A Sentinel signal
alone does not become a candidate. A tool finding is not proof of a security
issue, and a confirmed issue is not automatically reportable. Human
adjudication is required.

Each surviving local case should preserve repository/commit, location, raw and
normalized Sentinel evidence, corroborating evidence, source/sink and flow when
available, affected component/version, preconditions, impact, confidence,
disposition, open questions, and recommended next investigation. Patch and
disclosure documents are drafts only. The runner must not push, open a PR or
issue, publish an advisory, or contact a maintainer.

## Coverage and safety boundaries

The Cloud scanner currently does not expose parsed-file counts or parser-error
counters. Therefore the runner records `ENGINE_COVERAGE_UNMEASURED`, uses null
for parsed/eligible/parse-error counts, and does not claim `analysisCompleted`.
The engine's `filesScanned` value is not relabeled as parsed coverage. A zero
signal is not “clean”; it means only that no actionable signal was emitted by
this run, with coverage unmeasured.

Third-party repositories stay local. The audit runner does not upload source to
Sentinel Cloud hosted services. Campaign output is explicitly labeled
`Sentinel Cloud local engine; production parity unverified` while parity is
unknown. Parser coverage remains a stated limitation, not a fabricated metric.
