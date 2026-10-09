# Phase 4 — OWASP Benchmark Java v1.2: Specialist Evaluation and Routing Verification

**Generated:** 2026-10-09T02:23:59.409Z  
**Corpus:** OWASP Benchmark Java v1.2 (N=2740)  
**Dataset:** 2,740 test cases, evaluated against the ground truth in `expectedresults-1.2.csv`.  
**Specialist:** Semgrep `p/java` v1.175.0  
**CodeQL:** NOT_INSTALLED (not available for this phase)  
**AI/LLM:** DISABLED (LLM calls = 0, tokens = 0)  
**Execution Mode:** Multi-core parallel batch (-j 8)  

---

## Environment Freeze

| Key | Value |
|---|---|
| audit SHA | `d70c6ea8899438b67494d41570084884fe7fbc96` |
| semgrep | `1.175.0` |
| config | `p/java` |
| codeql | `NOT_INSTALLED` |
| AI / LLM reasoning | `DISABLED` (0 LLM calls) |
| build-mode | `none` (CodeQL flag, N/A) |
| routingVerification | `PHASE4_ROUTING_VERIFICATION.jsonl` (2,740 verified records) |

---

## Overall Results

| Metric | Value |
|---|---|
| Total test cases | **2740** |
| Analyzable (TP+TN+FP+FN) | **2740** |
| Errors / Unscannable | **0** |
| TRUE_POSITIVE (TP) | **995** |
| TRUE_NEGATIVE (TN) | **805** |
| FALSE_POSITIVE (FP) | **520** |
| FALSE_NEGATIVE (FN) | **420** |
| SPECIALIST_ERROR | 0 |
| TIMEOUT | 0 |
| UNSCANNABLE | 0 |

## Detection Metrics

| Metric | Formula | Value |
|---|---|---|
| TPR (Recall) | TP/(TP+FN) | **70.32%** |
| FPR | FP/(FP+TN) | **39.25%** |
| FNR | FN/(TP+FN) | 29.68% |
| Precision | TP/(TP+FP) | **65.68%** |
| Accuracy | (TP+TN)/N | **65.69%** |
| F1 | 2·P·R/(P+R) | **0.68** |
| **OWASP Score** | **(TPR−FPR)×100** | **31.07** |

> [!NOTE] OWASP Score is the Youden index scaled to [−100, 100]. Baseline random classifier = 0. The raw Sentinel Cloud baseline on this corpus scored: TPR=94.4%, FPR=95.0%, OWASP Score≈−0.6.

---

## Execution Timing & Throughput

| Metric | Value |
|---|---|
| Batch Wall Clock | **194.2 s** |
| Throughput | **~14.11 cases/second** |
| Average Amortized Timing | ~70.88 ms/case |
| Per-Case Timing Distribution | Not reported (batch amortized) |

> [!IMPORTANT]
> The batch scan completed in 194.2 seconds, equivalent to approximately 14.11 cases per second. Per-case latency percentiles (median/p95) are not reported because the exported result records reflect batch amortized timing rather than independently measured per-case timings.

---

## Routing Verification & Audit Traceability

Traceability between Sentinel Audit's routing architecture and the 2,740 test cases is documented in [`PHASE4_ROUTING_VERIFICATION.jsonl`](file:///C:/Users/sleyt/sentinel-audit/benchmark/phase4/PHASE4_ROUTING_VERIFICATION.jsonl):

- **Audit Run ID:** `audit-p4-routed-trace-20261008`
- **Language Detection:** Mapped via Audit's `EXT_LANG['.java']` → `java` (100% of cases).
- **Specialist Selection:** Audit's tool filter selected `semgrep` with `p/java` (CodeQL uninstalled; Bandit and ShellCheck incompatible with Java; Trivy/OSV inapplicable without package manifests).
- **Execution Provenance:** Cryptographically bound to raw batch output (SHA-256 `903845ef89d06d840da911576eeb7baf1449661102c5f1407c4df06d527e3854`).
- **Reconciliation:** 2,740 / 2,740 records (100%) match between Audit routing decisions and result classifications.

---

## Per-Category Breakdown

| Category | CWE | TP | TN | FP | FN | TPR | FPR | OWASP Score |
|---|---|---|---|---|---|---|---|---|
| pathtraver     | CWE-22  | 120 | 29 | 106 | 13 | 90.23% | 78.52% | 11.71 |
| hash           | CWE-328 | 89 | 107 | 0 | 40 | 68.99% | 0.00% | 68.99 |
| trustbound     | CWE-501 | 68 | 17 | 26 | 15 | 81.93% | 60.47% | 21.46 |
| crypto         | CWE-327 | 130 | 116 | 0 | 0 | 100.00% | 0.00% | 100.00 |
| cmdi           | CWE-78  | 112 | 29 | 96 | 14 | 88.89% | 76.80% | 12.09 |
| sqli           | CWE-89  | 234 | 89 | 143 | 38 | 86.03% | 61.64% | 24.39 |
| weakrand       | CWE-330 | 0 | 275 | 0 | 218 | 0.00% | 0.00% | 0.00 |
| ldapi          | CWE-90  | 26 | 4 | 28 | 1 | 96.30% | 87.50% | 8.80 |
| xss            | CWE-80  | 202 | 101 | 108 | 44 | 82.11% | 51.67% | 30.44 |
| securecookie   | CWE-614 | 0 | 31 | 0 | 36 | 0.00% | 0.00% | 0.00 |
| xpathi         | CWE-?   | 14 | 7 | 13 | 1 | 93.33% | 65.00% | 28.33 |

---

## Comparison: Raw Sentinel Cloud vs. Semgrep Java Specialist Arm

| Metric | Raw Cloud Baseline (Out-of-Scope) | Semgrep Specialist Arm (Phase 4) | Delta / Change |
|---|---|---|---|
| Corpus | OWASP Java v1.2 (N=2,740) | OWASP Java v1.2 (N=2,740) | Identical |
| TP | 1,336 | 995 | −341 |
| TN | 66 | 805 | **+739** |
| FP | 1,259 | 520 | **−739 (−58.7%)** |
| FN | 79 | 420 | +341 |
| TPR | 94.4% | 70.32% | −24.08 pp |
| FPR | 95.0% | 39.25% | **−55.75 pp** |
| OWASP Score | ≈ −0.6 | **+31.07** | **+31.67 points** |

> [!CAUTION]
> Compared with the historical raw Sentinel Cloud baseline on the same corpus, the Semgrep specialist arm produced 739 fewer false positives and reduced FPR by 55.75 percentage points. Because this comparison changes both the detector and the language-specialist configuration, the observed difference should not be attributed exclusively to the routing component.

---

*Phase 4 frozen. Traceability verified across all 2,740 cases.*
