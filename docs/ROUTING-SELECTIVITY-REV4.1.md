# Routing Selectivity Rev.4.1 — forensic closeout

**Status: HOLD for the 50+ repository campaign.** This is a read-only reconstruction from Rev.4 artifacts. No Cloud scan, specialist scan, target execution, engine edit, Purple/Oracle edit, commit, or push was performed.

## Evidence and definitions

Inputs are the Rev.4 aggregate and per-arm JSON under `docs/routing-selectivity-rev4/`, the recovered Rev.2 Cloud `sentinel.json` / `expediente.json` records in `%TEMP%\opencode\cloud-calibration-5\out\`, and the F/A/B Semgrep outputs in `%TEMP%\opencode\cloud-calibration-5\ab\`. The five exact pins and Semgrep version are those recorded in Rev.4; no cross-commit joins were made.

* **F**: explicit tracked-file universe from the saved full-universe Semgrep arm.
* **A (Rev.4)**: Semgrep pointed at the repository directory. This is not the same strategy as the promoted-directory simulation below.
* **B0**: the complete file shortlist promoted by Cloud; no 40-file cap.
* **A0**: offline membership replay over F findings/files, where each promoted file selects its immediate parent directory recursively. A root-level promoted file therefore selects the repository root. This is a derived target set, not an executed scan.
* **A1**: same replay after expanding each A0 directory by one parent level. Also not an executed scan.

## Finding-by-finding routing ledger

“Cloud signal” is represented by the saved actionable-signal shortlist membership for that exact file. It answers whether Cloud gave routing an actionable signal on the file; it does not claim the signal semantically corresponds to the Semgrep rule. Directory membership is the exact parent directory selected by the A0 definition. Paths under `examples/`, `playgrounds/`, and `test/` are labeled non-production by location; this is a scope observation, not proof that every finding is benign.

| ID | Repo | File:line | Semgrep rule | Severity | Scope by path | F | A | B0 | Cloud signal on file | Cloud promoted file | A0 dir contains file | Why absent |
|---|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| F01 | express | `examples/auth/index.js:25` | `express-session-hardcoded-secret` | HIGH | NON_PRODUCTION | yes | yes | yes | yes | yes | yes | — |
| F02 | express | `examples/mvc/index.js:43` | `express-session-hardcoded-secret` | HIGH | NON_PRODUCTION | yes | yes | yes | yes | yes | yes | — |
| F03 | express | `examples/session/index.js:19` | `express-session-hardcoded-secret` | HIGH | NON_PRODUCTION | yes | yes | no | no | no | no | Cloud did not promote this file or its immediate directory |
| F04 | express | `examples/session/redis.js:23` | `express-session-hardcoded-secret` | HIGH | NON_PRODUCTION | yes | yes | no | no | no | no | Cloud did not promote this file or its immediate directory |
| F05 | fastify | `test/server.test.js:102` | `react-insecure-request` | MEDIUM | TEST | yes | no | yes | yes | yes | yes | A's directory scan skips this test file; B0 selects it |
| F06 | svelte | `packages/svelte/scripts/check-treeshakeability.js:90` | `unknown-value-with-script-tag` | LOW | UNKNOWN (scripts path) | yes | yes | yes | yes | yes | yes | — |
| F07 | svelte | `packages/svelte/src/compiler/migrate/index.js:363` | `unknown-value-with-script-tag` | LOW | PRODUCTION-CODE PATH | yes | yes | yes | yes | yes | yes | — |
| F08 | svelte | `playgrounds/sandbox/scripts/download.js:115` | `detect-child-process` | HIGH | NON_PRODUCTION | yes | yes | yes | yes | yes | yes | — |
| F09 | svelte | `playgrounds/sandbox/scripts/download.js:130` | `detect-child-process` | HIGH | NON_PRODUCTION | yes | yes | yes | yes | yes | yes | — |
| F10 | svelte | `playgrounds/sandbox/scripts/download.js:168` | `detect-child-process` | HIGH | NON_PRODUCTION | yes | yes | yes | yes | yes | yes | — |
| F11 | svelte | `playgrounds/sandbox/scripts/download.js:172` | `detect-child-process` | HIGH | NON_PRODUCTION | yes | yes | yes | yes | yes | yes | — |
| F12 | svelte | `playgrounds/sandbox/scripts/download.js:506` | `unknown-value-with-script-tag` | LOW | NON_PRODUCTION | yes | yes | yes | yes | yes | yes | — |
| F13 | flags | `examples/shirt-shop/scripts/install.mjs:5` | `detect-child-process` | HIGH | NON_PRODUCTION | yes | yes | yes | yes | yes | no | File was promoted, but its immediate directory was not selected by the A0 parent-directory set |
| F14 | swr | `scripts/bump-next-version.js:19` | `detect-child-process` | HIGH | UNKNOWN (scripts path) | yes | yes | yes | yes | yes | yes | — |

The two Express findings at `examples/session/{index.js:19,redis.js:23}` are exactly the two B0 losses: **A recovers both; A does not recover either.** The additional A omission is Fastify `test/server.test.js:102`, which B0 recovers. Thus A=13/14 and B0=12/14 against the saved F findings, but A's 13/14 is not a Cloud-promoted-directory experiment.

Semgrep's concrete HIGH evidence for the two Express rows is the rule `javascript.express.security.audit.express-session-hardcoded-secret.express-session-hardcoded-secret`; its saved message says a hard-coded credential was detected. The artifact does not preserve a source snippet or a secret value, so this report does not reproduce one. Both paths are under `examples/session/`, and both have zero actionable Cloud signals and are absent from the shortlist. The Rev.2 run identity records policy SHA-256 `2359323cc45da4b3384f76d102580049a57601d7d11bf3342cfb2a6bbe3d26a6`; this exactly matches `HEAD:config/policies.json`. That policy explicitly lists `/examples/` in `coverage.nonProductionPathHints`, and the correlator excludes non-production findings from candidate promotion while retaining raw inputs. Therefore these findings are **OUT_OF_SCOPE for the production-candidate KPI**, not evidence of production routing recall loss. They remain coverage blind spots for any broader all-repository security scope. The Rev.4 narrative saying examples were not excluded conflicts with the exact policy and run identity; this is a report inconsistency. The saved run proves no actionable Cloud signal and no shortlist promotion, but cannot distinguish an absent detector from one that did not fire, and has no per-file parser telemetry. Exact engine root cause remains **ROOT_CAUSE_UNKNOWN**.

## Granularity and cost

| Strategy | Files in measured universe | Files vs F | Findings observed | Recall vs 14 F findings | Lost F findings | Wall time / CPU |
|---|---:|---:|---:|---:|---|---|
| F full-universe arm | 10,853 | 100% | 14 | 100% of measured F | none in F | F timing is batched and explicitly not comparable |
| A, Rev.4 repository-directory scan | 1,798 scanned | 16.6% | 13 | 92.9% | F05 (directory scanner skipped test path) | 277,977 ms; CPU/RSS per repo in Rev.4 JSON |
| B0 file shortlist | 413 | 3.8% | 12 | 85.7% | F03, F04 | 225,867 ms; CPU/RSS per repo in Rev.4 JSON |
| A0 promoted immediate directories (offline replay) | 9,847 known F files selected | 90.7% | 13 | 92.9% of measured F | F13 | not measured; no scan or resource cost inferred |
| A1 A0 plus one parent level (offline replay) | 10,853 known F files selected | 100% | 14 | 100% of measured F | none in measured F | not measured; no scan or resource cost inferred |

A0/A1 figures are set-membership replay from saved `filesScannedList`, shortlist paths, and F findings. They do **not** include the 64 Svelte paths rejected by Semgrep because `$` made the CLI batch abort; those files' finding outcomes are unknown. Thus “100%” for A1 means 14/14 findings in the saved measurable F set, not proven full-repository recall. Root-level promoted files select `.` under this explicit directory definition, which explains why A0 expands to all known files in Express, Fastify, and Svelte; A1 expands Flags/SWR to the full known repo universe. Do not treat these as executed tool coverage.

Surface reduction is not time reduction. The only measured timing comparison is Rev.4's A repository-directory execution against B0: B0 was 18.7% faster in aggregate, with large fixed Semgrep startup cost; that is not an A0/A1 timing result. A0 leaves only about 9.3% known-file reduction from F and loses one measured finding. A1 has no known-file reduction. No defensible cost-saving claim exists for promoted-directory routing from these artifacts.

## Coverage state proposal (not implemented)

Keep execution and coverage orthogonal:

```text
engineExecutionComplete: boolean | null
engineIncomplete: boolean
coverageKnown: boolean
coverageUnknown: boolean
filesScanned: integer | null
filesFailed: integer | null
alertsFailed: integer | null
```

`engineIncomplete=false` means only that the invocation did not report an execution failure. It does not mean all security classes, files, or parser paths were covered. When coverage telemetry is absent, set `coverageKnown=false`, `coverageUnknown=true`; never translate no findings to CLEAN. No implementation change was made in this forensic pass.

## Decision

**DIRECTORY ROUTING CANDIDATE — not an approved default and not a cost-saving claim.** The offline A0 replay retains 13/14 measured findings (92.9%); its single miss is the HIGH finding in `examples/shirt-shop/scripts/install.mjs`. The verified policy classifies `examples/` as NON_PRODUCTION, so this miss is out-of-scope for the production-candidate KPI but remains visible for broader scope. A0 selects 90.7% of the known file universe, and actual A/A0 wall-time equivalence was not measured. A1 offers no measured surface reduction and its 14/14 is limited to F's measured set. A controlled pilot may be justified only after root-level file handling is explicitly specified (root-level files must not silently promote the entire repo) and coverage unknowns remain visible. **No 50+ campaign.**

## Closing answers

1. **What is demonstrated:** the two Express HIGH secret findings are exactly B0's losses; both are recovered by A, while A loses the Fastify test finding. Cloud did not emit actionable signals on the Express session files. The run's policy hash matches the current pinned policy, which explicitly classifies `examples/` as NON_PRODUCTION; Rev.4's contrary scope statement is inconsistent with its recorded policy. A0/A1 membership can be replayed from saved F artifacts, with the counts and limitations above.
2. **What is not demonstrated:** Cloud parser coverage or the precise detector root cause; whether the two Express findings would be relevant under a broader-than-production scope; any coverage of the 64 Semgrep-rejected Svelte paths; executed A0/A1 performance; production parity; or that directory routing saves meaningful time.
3. **Does directory routing merit a controlled pilot?** Candidate only, not production default: A0's 92.9% measured-F recall meets the numeric gate, but 90.7% file surface remains and runtime was not measured. Specify root-level handling first.
4. **What Cloud must resolve before 50+:** make coverage unknown explicit in run verdicts; keep execution completeness distinct from security coverage; investigate the no-signal Express secret pattern without forcing a rule hit; and retain per-file failure/coverage evidence where the engine exposes it. Until then a routed absence is “not selected,” never “clean.”
