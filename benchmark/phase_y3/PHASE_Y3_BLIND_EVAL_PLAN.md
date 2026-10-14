# Phase Y3 — Blind Evaluation Plan: Package-Disjoint Differential Benchmark

**Document Version:** 1.0.0  
**Status:** PRE-REGISTERED (Frozen prior to execution)  
**Evaluator Engine:** Sentinel Y v0.1.0-alpha (`C:\Users\sleyt\sentinel-audit\sentinel-y\index.js`)  
**Baseline Engine:** CodeQL 2.27.1 (`javascript-queries@2.4.6`)  
**Reference Results:** `benchmark/phase_y1/PHASE_Y1_REFERENCE_MATRIX.json`  

---

## 1. Scientific Objective & Hypothesis

In Phase Y2, Sentinel Y demonstrated **100% paired discrimination (4/4)** on the four discovery cases (`deep-extend`, `mixin-deep`, `tough-cookie`, `cross-spawn`). However, because those four cases were used to calibrate the invariant models, that result does not constitute proof of generalization.

**Phase Y3 addresses the central experimental question:**
> *Does Sentinel Y generalize the invariant detection principles across packages and codebases it was not calibrated against, and can it discriminate patched from vulnerable revisions more accurately or efficiently than static analysis baselines (CodeQL) without inflating false positive alarms on benign code?*

### Formal Hypotheses
- **H1 (Generalization):** Sentinel Y will detect and discriminate prototype pollution and ReDoS patterns in package-disjoint targets where the vulnerability mechanism aligns with the modeled structural invariants.
- **H2 (Specificity):** Sentinel Y will maintain a False Positive Rate (FPR) $\le 10\%$ on negative benign controls.
- **H3 (Comparative Ground Truth):** In cases where CodeQL failed to discriminate due to persistent over-tainting or coarse regex approximations, Sentinel Y's invariant tracking will demonstrate distinct failure/success modes verifiable through git diff analysis.

---

## 2. Inviolable Experimental Controls

1. **Strict Package Disjointness:**  
   The four development/calibration packages are permanently excluded from Phase Y3 primary metric calculations:
   - `deep-extend` (P5-013) — EXCLUDED
   - `mixin-deep` (P5-015) — EXCLUDED
   - `tough-cookie` (P5-033) — EXCLUDED
   - `cross-spawn` (P5-041) — EXCLUDED

2. **Frozen Engine Invariant:**  
   The Sentinel Y codebase (`sentinel-y/index.js`) remains strictly immutable during the evaluation. No rule tweaks, special-case additions, or threshold adjustments are permitted during or after running the blind evaluation suite.

3. **Runtime Isolation:**  
   Zero execution of target source code or build scripts. No `npm install`, `node`, or dynamic hooks. Zero runtime calls to external analyzers (CodeQL CLI / Semgrep CLI) during Sentinel Y evaluation passes.

4. **Identical Revision Pairs:**  
   Evaluations use the exact git commit SHAs, files, and repositories established in the Phase 5 Ground Truth manifest (`PHASE5_MANIFEST.json`) and Phase Y1 Reference Matrix.

---

## 3. Benchmark Corpus Composition

The blind evaluation corpus consists of **20 targets** divided into three evaluation panels:

### Panel A: Prototype Pollution (CWE-1321) — 7 Blind Pairs
Targets with verified public CVEs and patch diffs modifying object property assignment or iteration:

| Case ID | Package Name | CVE | Advisory ID | Target File | Clone Directory |
|---|---|---|---|---|---|
| P5-007 | `mongoose` | CVE-2023-3696 | GHSA-9m93-w8w6-76hh | `lib/document.js` | `Automattic_mongoose` |
| P5-011 | `minimist` | CVE-2021-44906 | GHSA-xvch-5gv4-984h | `index.js` | `minimistjs_minimist` |
| P5-014 | `set-value` | CVE-2019-10747 | GHSA-4g88-fppr-53pp | `index.js` | `jonschlinkert_set-value` |
| P5-016 | `json-pointer` | CVE-2022-4742 | GHSA-6xrf-q977-5vgc | `index.js` | `manuelstofer_json-pointer` |
| P5-018 | `lodash` | CVE-2018-16487 | GHSA-4xc9-xhrj-v574 | `lodash.js` | `lodash_lodash` |
| P5-029 | `json5` | CVE-2022-46175 | GHSA-9c47-m6qq-7p4h | `src/parse.js` | `json5_json5` |
| P5-038 | `async` | CVE-2021-43138 | GHSA-fwr7-v2mv-hh25 | `lib/internal/iterator.js` | `caolan_async` |

### Panel B: Regular Expression Denial of Service (CWE-1333) — 6 Blind Pairs
Targets with verified public CVEs and patch diffs modifying regular expressions:

| Case ID | Package Name | CVE | Advisory ID | Target File | Clone Directory |
|---|---|---|---|---|---|
| P5-020 | `moment` | CVE-2017-18214 | GHSA-446m-jvh8-3444 | `src/lib/parse/regex.js` | `moment_moment` |
| P5-027 | `ansi-regex` | CVE-2021-3807 | GHSA-93q8-gq69-wqmw | `index.js` | `chalk_ansi-regex` |
| P5-028 | `braces` | CVE-2024-4068 | GHSA-grv7-fg5c-x5vh | `index.js` | `micromatch_braces` |
| P5-030 | `semver` | CVE-2022-25883 | GHSA-c2qf-rxjj-qqgw | `semver.js` | `npm_node-semver` |
| P5-031 | `semver` | CVE-2015-8855 | GHSA-x6fg-f45m-jf5q | `semver.js` | `npm_node-semver` |
| P5-039 | `debug` | CVE-2017-20165 | GHSA-9vvw-cc9w-f27h | `src/node.js` | `debug-js_debug` |

### Panel C: Benign Negative Controls — 7 Negative Packages
Packages with no history of prototype pollution or ReDoS in the evaluated modules, evaluated across clean commits to measure false alarm propensity:

| Control ID | Package Name | Baseline Revision SHA | Evaluated Source File | Clone Directory | Expected Result |
|---|---|---|---|---|---|
| CTRL-01 | `axios` | `v1.7.0` (`c0a37db8`) | `lib/adapters/http.js` | `axios_axios` | 0 findings |
| CTRL-02 | `node-fetch` | `v2.6.7` (`a805bf77`) | `src/index.js` | `node-fetch_node-fetch` | 0 findings |
| CTRL-03 | `jsonwebtoken` | `v8.5.1` (`0c5bcf07`) | `index.js` | `auth0_node-jsonwebtoken` | 0 findings |
| CTRL-04 | `nodemailer` | `v6.6.0` (`5b3bc852`) | `lib/nodemailer.js` | `nodemailer_nodemailer` | 0 findings |
| CTRL-05 | `ejs` | `v3.1.6` (`ef440c9d`) | `lib/ejs.js` | `mde_ejs` | 0 findings |
| CTRL-06 | `marked` | `v4.0.0` (`e585f6e8`) | `src/Lexer.js` | `markedjs_marked` | 0 findings |
| CTRL-07 | `ws` | `v8.17.1` (`6bc75510`) | `lib/websocket.js` | `websockets_ws` | 0 findings |

---

## 4. Evaluation Metrics & Formulas

For each target pair $i$, let $V_i \in \{0, 1\}$ denote whether Sentinel Y alerts on the vulnerable revision, and $P_i \in \{0, 1\}$ denote whether it alerts on the patched revision.

1. **Paired Patch Discrimination Rate ($PDR$):**
   $$PDR = \frac{\sum_{i=1}^{N_{pairs}} [V_i = 1 \land P_i = 0]}{N_{pairs}}$$

2. **Persistent False Alarm Rate ($PFAR$):**
   $$PFAR = \frac{\sum_{i=1}^{N_{pairs}} [V_i = 1 \land P_i = 1]}{N_{pairs}}$$

3. **False Negative Rate ($FNR$):**
   $$FNR = \frac{\sum_{i=1}^{N_{pairs}} [V_i = 0]}{N_{pairs}}$$

4. **Inverted Discrimination Rate ($IDR$ - Anomalous):**
   $$IDR = \frac{\sum_{i=1}^{N_{pairs}} [V_i = 0 \land P_i = 1]}{N_{pairs}}$$

5. **Benign Control False Alarm Rate ($FPR_{ctrl}$):**
   $$FPR_{ctrl} = \frac{\sum_{j=1}^{N_{ctrl}} [Alert_j = 1]}{N_{ctrl}}$$

---

## 5. Pre-Registered Adjudication Categories

Each evaluation result is deterministically assigned to exactly one of the following classes:

| Class Code | Name | Operational Criteria | Scientific Interpretation |
|---|---|---|---|
| `TD` | True Discrimination | $V=1 \land P=0$ with alert matching CVE mechanism | Engine successfully detected flaw and validated patch |
| `FN` | False Negative (Missed) | $V=0 \land P=0$ | Mechanism fell outside modeled invariant boundaries |
| `PFA` | Persistent False Alarm | $V=1 \land P=1$ identical pattern fires on both revisions | Invariant lacks patch-recognition or guard tracking fails |
| `ID` | Inverted Discrimination | $V=0 \land P=1$ | Defect introduced or anomalous rule trigger |
| `TN` | True Negative (Control) | Control target generates 0 alerts | Clean specific pass on benign code |
| `FP` | False Positive (Control) | Control target generates $\ge 1$ alert | Over-generalized rule firing on benign constructs |

---

## 6. Execution Protocol

1. Checkout each git revision into ephemeral git worktrees.
2. Execute `analyzeFile(filePath, sourceContent)` via Sentinel Y.
3. Record findings in `PHASE_Y3_RESULTS.jsonl`.
4. Run comparison against CodeQL Phase Y1 reference findings for identical revisions.
5. Generate `PHASE_Y3_METRICS.json` and formal comparative report.
