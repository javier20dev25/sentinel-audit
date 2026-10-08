# Phase 4 — OWASP Benchmark Java v1.2

**Generated:** 2026-10-08T20:25:22.042Z  
**Corpus:** OWASP Benchmark Java v1.2 (N=2740)  
**Specialist:** Semgrep `p/java` v1.175.0  
**CodeQL:** NOT_INSTALLED (not available for this phase)  
**AI/LLM:** DISABLED (LLM calls = 0)  
**Workers:** 8 | **Timeout/file:** 120000ms  

---

## Environment Freeze

| Key | Value |
|---|---|
| audit SHA | `d70c6ea8899438b67494d41570084884fe7fbc96` |
| semgrep | `1.175.0` |
| config | `p/java` |
| codeql | `NOT_INSTALLED` |
| AI | `DISABLED` |
| build-mode | `none` (CodeQL flag, N/A) |

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
| Precision | TP/(TP+FP) | 65.68% |
| Accuracy | (TP+TN)/N | 65.69% |
| F1 | 2·P·R/(P+R) | 0.68 |
| **OWASP Score** | **(TPR−FPR)×100** | **31.07** |

> [!NOTE] OWASP Score is the Youden index scaled to [−100, 100]. Baseline random classifier = 0. The raw Sentinel Cloud baseline on this corpus scored: TPR=94.4%, FPR=95.0%, OWASP Score≈−0.6.

---

## Latency

| Metric | Value |
|---|---|
| Median | 71 ms |
| Mean | 71 ms |
| P95 | 71 ms |
| N (timed) | 2740 |

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

## Comparison: Raw Sentinel Cloud vs. Semgrep Java (Language-Aware Routing)

| Metric | Raw Cloud (Phase 2A baseline) | Semgrep Java (Phase 4) |
|---|---|---|
| Corpus | OWASP Java v1.2 (N=2,740) | OWASP Java v1.2 (N=2,740) |
| TP | 1,336 | 995 |
| TN | 66 | 805 |
| FP | 1,259 | 520 |
| FN | 79 | 420 |
| TPR | 94.4% | 70.32% |
| FPR | 95.0% | 39.25% |
| OWASP Score | ≈ −0.6 | 31.07 |

> [!IMPORTANT] The raw Cloud baseline is out-of-language-scope for Java: it applies JS/TS heuristics to Java source. The comparison isolates the routing benefit — not an engine quality improvement.

---

*Phase 4 frozen. Do not re-run without incrementing phase version and tagging corpus.*
