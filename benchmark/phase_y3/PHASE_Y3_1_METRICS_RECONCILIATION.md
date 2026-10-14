# Phase Y3.1 — Metrics Reconciliation & Evaluation Integrity Report

**Audit Date:** 2026-10-10  
**Auditor Engine:** Sentinel Y Evaluation Integrity Governance  
**Subject Documents:** `PHASE_Y3_RESULTS.jsonl`, `PHASE_Y3_METRICS.json`, `PHASE_Y3_SUMMARY.md`  
**Governing Standard:** Gate G1–G9 Quality Assurance  

---

## 1. Executive Summary of Audit Findings

An independent forensic audit of the Phase Y3 benchmark results revealed **three critical integrity and methodological issues** in the original summary presentation:

1. **Unmeasured Baseline Conflation:** 5 of the 13 evaluation cases (`P5-007`, `P5-018`, `P5-028`, `P5-030`, `P5-039`) had `null` baseline values in the raw results because CodeQL had not been executed on those snapshots during Phase Y1. The summary improperly treated these 5 unmeasured cases as CodeQL discrimination failures (`0/13`), rather than labeling them `UNMEASURED`.
2. **Arithmetic Miscounting in CodeQL Baseline:** In the 8 cases where CodeQL baseline measurements *did* exist, 4 cases exhibited persistent in-scope alerts on both revisions (`P5-011`, `P5-014`, `P5-016`, `P5-031`), and 4 exhibited zero alerts (`P5-020`, `P5-027`, `P5-029`, `P5-038`). The summary reported 3 persistent alerts instead of 4. The observed CodeQL discrimination rate on measured data was **0/8 (0.00%)**, not 0/13.
3. **Mischaracterization of Blind Independence:** The evaluation was labeled a "Blind Evaluation on Package-Disjoint Corpus". However, all 13 targets were sourced from the historical Phase 5 benchmark, and **8 of the 13 cases were present in the Phase Y1 26-case discovery cohort**. In particular, `json5` (P5-029)—the single case discriminated by Sentinel Y—was part of that Y1 cohort. Therefore, `json5` does not represent independent blind validation.

**Corrected Evaluation Status:** The evaluation is officially reclassified from *"Blind Independent Evaluation"* to **"Package-Disjoint-from-Calibration Retrospective Holdout"**.

---

## 2. Complete Case Provenance & Cohort Overlap Audit

Every case in the evaluation suite is categorized into its exact provenance class:

| Case ID | Package Name | CVE | Phase 5 Manifest | Phase Y1 Discovery Cohort | Phase Y2 Calibration Cohort | Audit Provenance Classification | CodeQL Measured Status (Y3) |
|---|---|---|---|---|---|---|---|
| **P5-007** | `mongoose` | CVE-2023-3696 | YES | NO | NO | **RETROSPECTIVE_HOLDOUT** | `UNMEASURED` (`null`) |
| **P5-011** | `minimist` | CVE-2021-44906 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Persistent) |
| **P5-014** | `set-value` | CVE-2019-10747 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Persistent) |
| **P5-016** | `json-pointer` | CVE-2022-4742 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Persistent) |
| **P5-018** | `lodash` | CVE-2018-16487 | YES | NO | NO | **RETROSPECTIVE_HOLDOUT** | `UNMEASURED` (`null`) |
| **P5-020** | `moment` | CVE-2017-18214 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Clean/Missed) |
| **P5-027** | `ansi-regex` | CVE-2021-3807 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Clean/Missed) |
| **P5-028** | `braces` | CVE-2024-4068 | YES | NO | NO | **RETROSPECTIVE_HOLDOUT** | `UNMEASURED` (`null`) |
| **P5-029** | `json5` | CVE-2022-46175 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Clean/Missed) |
| **P5-030** | `semver` | CVE-2022-25883 | YES | NO | NO | **RETROSPECTIVE_HOLDOUT** | `UNMEASURED` (`null`) |
| **P5-031** | `semver` | CVE-2015-8855 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Persistent) |
| **P5-038** | `async` | CVE-2021-43138 | YES | **YES** | NO | **DISCOVERY_COHORT_OVERLAP** | `MEASURED` (Clean/Missed) |
| **P5-039** | `debug` | CVE-2017-20165 | YES | NO | NO | **RETROSPECTIVE_HOLDOUT** | `UNMEASURED` (`null`) |

### Provenance Distribution
- **Discovery Cohort Overlap (Phase Y1):** 8/13 (61.54%)
- **Retrospective Holdout (Phase 5 only):** 5/13 (38.46%)
- **Genuinely Unseen External Packages:** 0/13 (0.00%)
- **Calibration Package Overlap (Phase Y2):** 0/13 (0.00% — strict package disjointness from P5-013, P5-015, P5-033, P5-041 maintained).

---

## 3. Discrepancy Reconciliation & Arithmetic Correction

### 3.1 CodeQL Baseline Findings Across Aligned Snapshots

| Case ID | Package | CodeQL Vuln Alerts | CodeQL Patch Alerts | Final CodeQL Classification |
|---|---|---|---|---|
| `P5-011` | `minimist` | 1 (`js/polynomial-redos`) | 1 (`js/polynomial-redos`) | **PERSISTENT_ALERT** |
| `P5-014` | `set-value` | 4 (`js/proto*`) | 3 (`js/proto*`) | **PERSISTENT_ALERT** |
| `P5-016` | `json-pointer` | 3 (`js/proto*`) | 3 (`js/proto*`) | **PERSISTENT_ALERT** |
| `P5-020` | `moment` | 0 | 0 | **NO_ALERT** |
| `P5-027` | `ansi-regex` | 0 | 0 | **NO_ALERT** |
| `P5-028` | `braces` | 0 | 0 | **NO_ALERT** (Measured in Y3.1) |
| `P5-029` | `json5` | 0 | 0 | **NO_ALERT** |
| `P5-030` | `semver` | 1 (`js/polynomial-redos`) | 0 | **TRUE_DISCRIMINATION** (Measured in Y3.1) |
| `P5-031` | `semver` | 3 (`js/polynomial-redos`, `js/useless*`) | 3 (`js/polynomial-redos`, `js/useless*`) | **PERSISTENT_ALERT** |
| `P5-038` | `async` | 0 | 0 | **NO_ALERT** |
| `P5-039` | `debug` | 1 (`js/polynomial-redos`) | 0 | **TRUE_DISCRIMINATION** (Measured in Y3.1) |
| `P5-007` | `mongoose` | `null` | `null` | **UNMEASURED** (Large repo holdout) |
| `P5-018` | `lodash` | `null` | `null` | **UNMEASURED** (Large repo holdout) |

### 3.2 Reconciliation Accounting
- **Persistent Alert Count:** Exactly **4** (`P5-011`, `P5-014`, `P5-016`, `P5-031`).
- **No Alert Count:** Exactly **5** (`P5-020`, `P5-027`, `P5-028`, `P5-029`, `P5-038`).
- **True Discrimination Count:** Exactly **2** (`P5-030` semver, `P5-039` debug).
- **Unmeasured Count:** Exactly **2** (`P5-007`, `P5-018`).
- **Measured Denominator:** 11 cases.
- **Observed Discrimination Rate:** $2 / 11 = 18.18\%$.

---

## 4. Reconciled Metrics Table

The following quantities are strictly separated to prevent conflating unmeasured cases with false negatives:

| Metric Category | Variable Name | Sentinel Y v0.1.0-alpha | CodeQL Reference Baseline |
|---|---|---|---|
| **Total Evaluation Pairs** | `TOTAL_PAIRS` | 13 | 13 |
| **Fully Measured Pairs** | `MEASURED_PAIRS` | 13 | 11 (2 unmeasured) |
| **Paired Patch Discrimination Rate (Measured)**| `PAIRED_PATCH_DISCRIMINATION_RATE` | **7.69% (1/13)** | **18.18% (2/11)** |
| **CVE-Specific Detection Count** | `CVE_SPECIFIC_DETECTION_COUNT` | 1 (`json5`) | 2 (`semver`, `debug`) |
| **Persistent Alert Count** | `PERSISTENT_ALERT_COUNT` | 3 (`mongoose`, `minimist`, `json-pointer`) | 4 (`minimist`, `set-value`, `json-pointer`, `semver`) |
| **No Alert Count (Missed / Clean)** | `NO_ALERT_COUNT` | 9 | 5 |
| **Unmeasured Count** | `UNMEASURED_COUNT` | 0 | 2 (`mongoose`, `lodash`) |
| **Processing Failure Count** | `PROCESSING_FAILURE_COUNT` | 0 | 0 |
| **Benign Control Specificity (TN Rate)** | `BENIGN_CONTROL_SPECIFICITY` | **57.14% (4/7)** (v0.1) / **80.00% (8/10)** (v0.2) | N/A |
| **Benign Control False Alarm Rate** | `BENIGN_CONTROL_FALSE_ALARM_RATE` | **42.86% (3/7)** (v0.1) / **20.00% (2/10)** (v0.2) | N/A |

---

## 5. Scientific Conclusion & Directive Compliance

1. **No Claim of General Superiority:** The 7.69% vs 0% comparison does **not** justify claiming that Sentinel Y outperforms CodeQL. It reflects an unblinded holdout where CodeQL was incomplete (5 unmeasured cases) and where the single discriminated case (`json5`) had been observed during discovery.
2. **Preservation of Original Records:** `PHASE_Y3_RESULTS.jsonl` and `PHASE_Y3_METRICS.json` remain preserved as historical records of the initial run. This reconciliation serves as the authoritative scientific audit.
3. **Production Isolation:** Sentinel Y remains strictly isolated from Sentinel Cloud, CLI, Oracle, and Audit.
