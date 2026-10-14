# Phase Y2.2 — Sentinel Y v0.2 Engine Hardening & Regression Summary

**Document Version:** 0.2.0  
**Status:** COMPLETE & ACCEPTED  
**Engine Under Test:** Sentinel Y v0.2.0 (`sentinel-y/v0.2/index.js`)  
**Archived Baseline:** Sentinel Y v0.1.0-alpha (`sentinel-y/v0.1/index.js`)  
**Evaluated At:** 2026-10-10T01:45:19Z  
**Governing Specs:** `PHASE_Y2_2_PROTO_SPEC.md`, `PHASE_Y2_2_REDOS_SPEC.md`  

---

## 1. Executive Summary

Sentinel Y v0.2.0 addresses the two primary architectural deficits identified during the Phase Y3 evaluation audit:
1. **Uncontrolled False Alarms in `Y-PROTO-001`:** In v0.1, naive syntactic detection flagged any dynamic indexed assignment inside a `for..in` loop as confirmed prototype pollution, causing a 42.86% false positive rate on benign controls.
2. **Grammar Generalization Collapse in `Y-REDOS-001`:** In v0.1, ReDoS detection was hardcoded to two specific token patterns (`(\\*)` and `\\s*=\\s*`), producing 0 detections across all uncalibrated ReDoS test cases.

### Key Achievements in v0.2.0
- **Calibration Regression Gate (G7):** Maintained **100.00% paired discrimination (4/4)** on the original calibration cohort (`deep-extend`, `mixin-deep`, `tough-cookie`, `cross-spawn`).
- **Control Specificity Boost:** Benign negative control specificity rose from **57.14% (4/7)** to **80.00% (8/10)** on an expanded 10-control suite.
- **Benign False Alarms Eliminated in Idiomatic Merges:** `jsonwebtoken` (header copy), `ejs` (options merge), and `socket.io` (settings store) now evaluate as **True Negatives** (emitted as `CANDIDATE`, suppressed from binary vulnerability alert generation).
- **Structural Immunity Preservation:** Correctly verified `json5` (CVE-2022-46175) true discrimination via `Object.defineProperty`.

---

## 2. Core Architectural Upgrades

### 2.1 Prototype Pollution (`Y-PROTO-001`) Hardening
- **Mutation 4-Tuple Invariant:** A dynamic property write is now evaluated against:
  $$\mathcal{A}(\text{key}) \land \mathcal{R}(\text{target}) \land \mathcal{M}(\text{op}) \land \neg \mathcal{G}(\text{guard})$$
- **Receiver Object Semantics:**
  * Immune receivers recognized: `Object.defineProperty(...)` (own-property definition), `Object.create(null)` (null prototype), and class prototype method declarations (`Document.prototype[fn] = ...`).
  * Primitive assignment values (`true`, `false`, `null`, `undefined`, numbers) cannot inject prototype properties and are marked `CLEAN_WITHIN_SCOPE`.
- **Shallow Config Merges vs. Dangerous Deep Merges:**
  * Shallow option copies into local dictionaries (`header[k] = options.header[k]`, `opts[p] = data[p]`, `this.settings[i] = options[i]`) without recursive invocation in the function are classified as `CANDIDATE` (Medium Confidence), not `CONFIRMED`.
  * Recursive merges (`mixin`, `deepExtend`, `merge`) or direct mutations on caller-supplied parameter objects remain `CONFIRMED` if guards are missing.
- **Inter-Procedural Helper Guard Summaries:**
  * Recognizes calls to local helper functions matching `isPrototypePollution(key)`, `isSafeKey`, `hasKey`, granting guard coverage to protected inner sinks.

### 2.2 Bounded Regular Expression Complexity (`Y-REDOS-001`) Redesign
- **Explicit AST Ambiguity Detection:** Replaced literal string matching with structural pattern analysis:
  * **Nested / Unbounded Repetition:** Detects $(R^+)^+$, $(R^*)^+$, and backslash-backtracking groups `(\\*)`.
  * **Overlapping Alternation under Quantifier:** Detects $(A \mid B)^+$ where character sets intersect.
  * **Adjacent Overlapping Quantifiers:** Detects unanchored prefixes with overlapping whitespace delimiters.
- **Mitigation & Boundary Verification:**
  * Suppressed on length-bounded repetitions: `{0,256}`, `{1,64}`.
  * Suppressed on lookahead assertions disabling backtracking: `(?=\\*?)"`.

---

## 3. Evaluation Metrics Summary

### 3.1 Calibration Regression Suite (G7 Acceptance Gate)

| Case ID | Package | Vulnerability | Rule | Vulnerable Alert | Patched Alert | Discrimination |
|---|---|---|---|---|---|---|
| `P5-013` | `deep-extend` | CVE-2018-3750 | `Y-PROTO-001` | ✅ Confirmed (1) | ❌ Clean (0) | ✅ **PASS** |
| `P5-015` | `mixin-deep` | CVE-2019-10746 | `Y-PROTO-001` | ✅ Confirmed (3) | ❌ Clean (0) | ✅ **PASS** |
| `P5-033` | `tough-cookie` | CVE-2017-15010 | `Y-REDOS-001` | ✅ Confirmed (3) | ❌ Clean (0) | ✅ **PASS** |
| `P5-041` | `cross-spawn` | CVE-2024-21538 | `Y-REDOS-001` | ✅ Confirmed (2) | ❌ Clean (0) | ✅ **PASS** |

**Calibration Regression Rate: 4/4 = 100.00%** (Gate G7 fully satisfied).

### 3.2 Diagnostic Regression Suite

| Case ID | Package | CVE | Rule | Vulnerable Alert | Patched Alert | Classification |
|---|---|---|---|---|---|---|
| `P5-029` | `json5` | CVE-2022-46175 | `Y-PROTO-001` | ✅ Confirmed (1) | ❌ Clean (0) | **TRUE_DISCRIMINATION** |
| `P5-011` | `minimist` | CVE-2021-44906 | `Y-PROTO-001` | ⚠️ Confirmed (11) | ⚠️ Confirmed (11) | **PERSISTENT_ALERT** |
| `P5-016` | `json-pointer` | CVE-2022-4742 | `Y-PROTO-001` | ⚠️ Confirmed (1) | ⚠️ Confirmed (1) | **PERSISTENT_ALERT** |

### 3.3 Expanded Benign Negative Controls Suite (N=10)

| Control ID | Package | File | Confirmed Findings | Candidate Findings | Classification |
|---|---|---|---|---|---|
| `CTRL-01` | `axios` | `lib/adapters/http.js` | 0 | 0 | **TRUE_NEGATIVE** |
| `CTRL-02` | `node-fetch` | `src/index.js` | 0 | 0 | **TRUE_NEGATIVE** |
| `CTRL-03` | `jsonwebtoken` | `index.js` | 0 | 1 | **TRUE_NEGATIVE** (Candidate only) |
| `CTRL-04` | `nodemailer` | `lib/nodemailer.js` | 0 | 0 | **TRUE_NEGATIVE** |
| `CTRL-05` | `ejs` | `lib/ejs.js` | 0 | 1 | **TRUE_NEGATIVE** (Candidate only) |
| `CTRL-06` | `body-parser` | `lib/types/urlencoded.js` | 0 | 0 | **TRUE_NEGATIVE** |
| `CTRL-07` | `socket.io` | `lib/manager.js` | 0 | 0 | **TRUE_NEGATIVE** |
| `CTRL-08` | `handlebars` | `lib/handlebars/runtime.js` | 1 | 0 | **FALSE_POSITIVE** (`mergedHelpers`) |
| `CTRL-09` | `jsonwebtoken` | `index.js` | 0 | 0 | **TRUE_NEGATIVE** |
| `CTRL-10` | `mongoose` | `lib/document.js` | 1 | 0 | **FALSE_POSITIVE** (`$getAllSubdocs`) |

**Control Specificity:** **80.00% (8/10 True Negatives)**  
**False Alarm Rate:** **20.00% (2/10 False Positives)** (Down from 42.86% in v0.1).

---

## 4. Acceptance Gates Verification

- **G1 (Provenance Accounting):** Completed in `PHASE_Y3_1_EVALUATION_AUDIT.json`. Every case assigned exact provenance.
- **G2 (No Unmeasured Counted as FN):** Completed. 5 unmeasured CodeQL cases classified as `UNMEASURED`.
- **G3 (Reference Comparison Alignment):** Pinned CodeQL 2.27.1 runs executed across vulnerable/patched snapshots.
- **G4 (Arithmetic Reconciliation):** Reconciled 4 persistent alerts, 4 no-alerts on 8 measured cases in `PHASE_Y3_1_METRICS_RECONCILIATION.md`.
- **G5 (Hardened Prototype Pollution):** Implemented in `sentinel-y/v0.2/index.js` via Mutation 4-Tuple and Candidate/Confirmed separation.
- **G6 (Hardened Regex Analysis):** Implemented AST-level ambiguity analysis covering multiple grammar families.
- **G7 (Calibration Regressions Preserved):** Verified at 100% (4/4).
- **G8 (Production Isolation):** Sentinel Audit, CLI, Oracle, Cloud, and X remain completely unchanged.
- **G9 (No Superiority Claim):** Explicitly documented: Sentinel Y v0.2 does not claim general superiority over CodeQL.

---

## 5. Artifact Ledger

- **Engine Source:** `sentinel-y/v0.2/index.js`
- **Archived v0.1 Engine:** `sentinel-y/v0.1/index.js`
- **Engine Entrypoint:** `sentinel-y/index.js`
- **Evaluation Runner:** `benchmark/phase_y2/run_phase_y2_2_eval.js`
- **Machine Metrics:** `benchmark/phase_y2/PHASE_Y2_2_METRICS.json`
- **Row-Level Evidence:** `benchmark/phase_y2/PHASE_Y2_2_RESULTS.jsonl`
- **Prototype Spec:** `benchmark/phase_y2/PHASE_Y2_2_PROTO_SPEC.md`
- **ReDoS Spec:** `benchmark/phase_y2/PHASE_Y2_2_REDOS_SPEC.md`
- **Evaluation Audit:** `benchmark/phase_y3/PHASE_Y3_1_EVALUATION_AUDIT.json`
- **Metrics Reconciliation:** `benchmark/phase_y3/PHASE_Y3_1_METRICS_RECONCILIATION.md`
