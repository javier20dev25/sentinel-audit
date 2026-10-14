# Phase Y3.1 — Final Execution & Forensic Metrics Reconciliation Report

**Document Version:** 1.1.0-AUDITED  
**Audit Date:** 2026-10-10  
**Status:** RECONCILED & FORENSICALLY VERIFIED  
**Governing Artifacts:** `PHASE_Y3_RESULTS.jsonl`, `benchmark/phase_y1/reference_runs/` (SARIF storage)  

---

## 1. Executive Summary: Forensic Re-audit of the Y3.1 Subcorpus

In accordance with Section A of the mandate, an exhaustive re-audit of `PHASE_Y3_RESULTS.jsonl` and the underlying CodeQL SARIF storage was conducted to resolve the arithmetic contradiction identified in earlier summary drafts.

### Root Cause of the Arithmetic Contradiction
Earlier draft text stated simultaneously that:
1. Sentinel Y detected the vulnerable revision in 4 cases (including `P5-014`).
2. Sentinel Y was clean in both revisions of `P5-014`.
3. Sentinel Y produced 3 persistent alerts (`P5-007`, `P5-011`, `P5-016`).
4. Sentinel Y discriminated only `P5-029`.

**The Definitive Truth (Reconstructed Directly from `PHASE_Y3_RESULTS.jsonl` Line 3):**
```json
{"caseId":"P5-014","panel":"A (Proto)","package":"set-value","cve":"CVE-2019-10747","rule":"Y-PROTO-001","file":"index.js","vulnerableSha":"7bd5011d","fixSha":"95e9d992","vAlert":false,"pAlert":false,"discriminated":false,"category":"FN","vFindingCount":0,"pFindingCount":0,"codeqlBaseline":{"vulnAlert":true,"patchAlert":true,"discriminated":false}}
```
- In `P5-014` (`set-value`), **Sentinel Y v0.1 generated 0 findings on the vulnerable revision and 0 findings on the patched revision** (`vAlert: false`, `pAlert: false`, `category: 'FN'`).
- Sentinel Y **DID NOT** detect the vulnerable revision of `P5-014`. It was a complete False Negative (`FN`) due to `set-value` implementing path-based property recursion rather than a simple enumerative `for..in` loop.
- The 3 persistent alerts produced by Sentinel Y in the full 13-case run were `P5-007` (`mongoose`), `P5-011` (`minimist`), and `P5-016` (`json-pointer`).
- In the 6-pair subcorpus where CodeQL is measured, `P5-007` is unmeasured. Therefore, within the common 6-pair subcorpus, Sentinel Y generated persistent alerts on **exactly 2 pairs** (`P5-011` and `P5-016`).

---

## 2. Row-by-Row Primary Evidence on Common Measured Subcorpus (N=6)

The common subcorpus consists strictly of the 6 pairs where both the vulnerable and patched revisions possess valid, verified, non-empty SARIF files on disk in `benchmark/phase_y1/reference_runs/`:

| Case ID | Package Name | Target File | Vulnerable SHA | Remediated SHA | Sentinel Y Vulnerable Alert | Sentinel Y Patched Alert | CodeQL Vulnerable Alert | CodeQL Patched Alert | Primary Evidence Artifacts |
|---|---|---|---|---|---|---|---|---|---|
| **P5-011** | `minimist` | `index.js` | `c0b26618` | `34e20b84` | **YES (11)** | **YES (11)** | **YES (1)** | **YES (1)** | `codeql_P5-011_vulnerable.sarif` (97 KB)<br>`codeql_P5-011_patched.sarif` (97 KB) |
| **P5-014** | `set-value` | `index.js` | `7bd5011d` | `95e9d992` | **NO (0)** | **NO (0)** | **YES (4)** | **YES (3)** | `codeql_P5-014_vulnerable.sarif` (141 KB)<br>`codeql_P5-014_patched.sarif` (138 KB) |
| **P5-016** | `json-pointer`| `index.js` | `9b5ea8e3` | `859c9984` | **YES (1)** | **YES (1)** | **YES (3)** | **YES (3)** | `codeql_P5-016_vulnerable.sarif` (98 KB)<br>`codeql_P5-016_patched.sarif` (98 KB) |
| **P5-029** | `json5` | `src/parse.js` | `072eb402` | `62a65408` | **YES (1)** | **NO (0)** | **NO (0)** | **NO (0)** | `codeql_P5-029_vulnerable.sarif` (91 KB)<br>`codeql_P5-029_patched.sarif` (91 KB) |
| **P5-031** | `semver` | `semver.js` | `a685e01b` | `5c4c9f6e` | **NO (0)** | **NO (0)** | **YES (3)** | **YES (3)** | `codeql_P5-031_vulnerable.sarif` (89 KB)<br>`codeql_P5-031_patched.sarif` (89 KB) |
| **P5-038** | `async` | `lib/internal/iterator.js` | `f1d8383b` | `8f7f9034` | **NO (0)** | **NO (0)** | **NO (0)** | **NO (0)** | `codeql_P5-038_vulnerable.sarif` (202 KB)<br>`codeql_P5-038_patched.sarif` (202 KB) |

---

## 3. Reconciled Metrics Table on Common Subcorpus (N=6)

Directly calculated via code from the row-level data above:

| Metric Category | Operational Definition | Sentinel Y v0.1.0-alpha | CodeQL 2.27.1 Baseline | Scientific Interpretation |
|---|---|---|---|---|
| **Pares Comunes Medidos** | Ambas revisiones completaron análisis con SARIF persistente | **6 / 6 (100.0%)** | **6 / 6 (100.0%)** | Denominador común estricto |
| **Alertas en Revisión Vulnerable** | Al menos 1 hallazgo relevante en revisión vulnerable | **3 / 6 (50.00%)** | **4 / 6 (66.67%)** | Y: P5-011, 016, 029<br>CodeQL: P5-011, 014, 016, 031 |
| **Alertas en Revisión Parcheada** | Al menos 1 hallazgo relevante en revisión parcheada | **2 / 6 (33.33%)** | **4 / 6 (66.67%)** | Y: P5-011, 016<br>CodeQL: P5-011, 014, 016, 031 |
| **Alertas Persistentes** | Alerta en vulnerable Y alerta en parcheada ($V=1 \land P=1$) | **2 / 6 (33.33%)** | **4 / 6 (66.67%)** | Y: P5-011, 016<br>CodeQL: P5-011, 014, 016, 031 |
| **Discriminación Pareada** | Alerta en vulnerable Y limpio en parcheada ($V=1 \land P=0$) | **1 / 6 (16.67%)** | **0 / 6 (0.00%)** | Y: P5-029 (`json5`)<br>CodeQL: Ninguno |
| **Sin Alertas en Ambas Revisiones** | Limpio en vulnerable Y limpio en parcheada ($V=0 \land P=0$) | **3 / 6 (50.00%)** | **2 / 6 (33.33%)** | Y: P5-014, 031, 038<br>CodeQL: P5-029, 038 |
| **Alertas Invertidas** | Limpio en vulnerable Y alerta en parcheada ($V=0 \land P=1$) | **0 / 6 (0.00%)** | **0 / 6 (0.00%)** | Ningún motor introdujo alertas fantasma |

---

## 4. Definitive Status of the 7 Unmeasured CodeQL Pairs

Under strict forensic standards, absence of an artifact or an unverified ephemeral terminal run **CANNOT** be converted into a measured negative (`NO_ALERT`) or a measured positive:

1. **`P5-007` (`mongoose`)**: UNMEASURED (Monorepo grande no incluido en lote Y1).
2. **`P5-018` (`lodash`)**: UNMEASURED (Monorepo grande no incluido en lote Y1).
3. **`P5-020` (`moment`)**: UNMEASURED (Fallo silencioso/timeout en lote Y1; ningún SARIF generado).
4. **`P5-027` (`ansi-regex`)**: UNMEASURED (Revisión parcheada sufrió timeout; solo existe SARIF vulnerable).
5. **`P5-028` (`braces`)**: UNMEASURED (Corrida efímera borró SARIF y DB; sin evidencia persistente).
6. **`P5-030` (`semver`)**: UNMEASURED (Corrida efímera borró SARIF y DB; sin evidencia persistente).
7. **`P5-039` (`debug`)**: UNMEASURED (Corrida efímera borró SARIF y DB; sin evidencia persistente).

**Impact on Claimed CodeQL Rate:** The previously claimed CodeQL rate of `18.18% (2/11)` is **CONTRADICTED** by repository evidence. The verified sample size is 6, yielding `0/6 (0.00%)`. The 7 unmeasured pairs remain strictly excluded from the baseline denominator.

---

## 5. Scope and Boundaries of the `json5` Detection

- **Signal Quality:** In `P5-029` (`json5` CVE-2022-46175), Sentinel Y detected the unsafe direct property write `value[key] = replacement` in `src/parse.js:50` and verified that the patch remediated the issue via `Object.defineProperty(...)`. This is a verified `CVE_SPECIFIC_CONFIRMED` detection.
- **Scientific Limitation:** `P5-029` was a member of the Phase Y1 26-case discovery cohort (`PHASE_Y1_DISCOVERY_COHORT.json`). Therefore, **this detection does not constitute evidence of blind out-of-sample generalization**. It proves semantic discrimination on a previously observed mechanism family, but cannot be extrapolated to predict performance on unseen packages.
