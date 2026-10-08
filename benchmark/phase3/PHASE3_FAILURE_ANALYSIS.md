# Phase 3 Failure & False Negative Analysis (NPMStudy N=4,301)

**Generated:** 2026-10-08T19:30:58.237Z  
**Target Universe:** 4,301 packages from NPMStudy `zip_malware`  
**Ground Truth:** ALL MALICIOUS  

---

## 1. Primary Metrics (Formal Nomenclature)

| Metric | Measured Value | Percentage / Calculation |
| :--- | :---: | :---: |
| **Scan Completion Rate** | **3,277 / 4,301** | **76.19%** |
| **Strict BLOCK Detection (all targets)** | **2,956 / 4,301** | **68.73%** |
| **Strict BLOCK Detection (analyzable)** | **2,956 / 3,277** | **90.20%** |
| **BLOCK + REVIEW Detection (all targets)** | **3,171 / 4,301** | **73.73%** |
| **BLOCK + REVIEW Detection (analyzable)** | **3,171 / 3,277** | **96.77%** |
| **Unscannable / Processing Exclusions** | **1,024 / 4,301** | **23.81%** |

---

## 2. Taxonomy of the 1,024 Unscannable / Unresolved Targets

The 1,024 non-analyzed targets represent **structural and intake boundaries**, not scanner detection failures:

```text
UNSCANNABLE TARGETS (1,024 / 4,301 = 23.81%)
├── Intermediate Archive Extension Mismatch (1,018 / 1,024 = 99.41%)
│     └── Outer .tgz decompressed to inner tar named *.tgz rather than *.tar
│         (Secondary extraction pass skipped by runner intake pattern)
└── Extraction / Path Boundary Errors (6 / 1,024 = 0.59%)
      └── Deep nested path / long filename boundary on Windows OS
```

### Root Cause Analysis:
1. **Archive Intake Limitation (1,018 packages, 99.4%):**
   In NPMStudy's scoped package mirrors (e.g., `@add-wallet-exchange##import-type`), tarballs were scraped such that the inner tar payload preserved the `*.tgz` filename in its gzip header. The benchmark runner expected `*.tar` as the intermediate artifact before walking files, skipping the inner extraction. These packages are structurally valid npm packages that can be processed by updating the extraction pipeline to inspect file magic headers (`Type = tar`) rather than file extensions.
2. **Decompression / OS Limits (6 packages, 0.6%):**
   Deeply nested directory structures (e.g., browser-extension stealers containing Firefox profile hierarchies with paths exceeding Windows MAX_PATH).

---

## 3. Root Cause Analysis of the 106 True False Negatives (PASS)

The 106 packages that completed scanning but received **PASS** represent the true evasion surface of the static + hybrid pipeline on this corpus:

```text
TRUE FALSE NEGATIVES (106 / 3,277 analyzable = 3.23%)
├── Complete Static Blindspot (46 packages / 43.40%)
│     └── 0 raw alerts across Cloud, CLI, and Oracle
└── Sub-Threshold Signal Suppression (60 packages / 56.60%)
      └── 1 to 5 Low/Medium signals, 0 Critical, 0 High, 0 Ambiguity triggers
```

### A. Complete Static Blindspot (46 packages)
- **Mechanism:** Dependency-confusion proof-of-concept packages containing benign utility stubs or single plain HTTP GET/POST callbacks without dynamic evaluation (`eval`), subprocess spawning (`child_process`), or obfuscation.
- **Why Missed:** Single un-obfuscated network requests in otherwise clean code are not flagged as malicious by static engines to avoid creating false positives on legitimate client libraries.

### B. Sub-Threshold Suppression (60 packages)
- **Mechanism:** Triggered low-confidence heuristic markers (e.g., `NETWORK_ACTIVITY`, `SNT-MEDI-001`, `building-block-network-import`).
- **Why Missed:** Sentinel Audit enforces a strict corroboration policy:
  - Requires $\ge 1$ CRITICAL, or $\ge 1$ HIGH, or $> 5$ MEDIUM alerts, or an ambiguous taint sink to escalate.
  - Packages with 1–4 MEDIUM or LOW alerts are intentionally suppressed to PASS to prevent enterprise alert fatigue.

---

## 4. Cross-Corpus Funnel Stability (Clustered Bootstrap Analysis)

To test whether the hybrid escalation rate is statistically consistent across different corpus types, a **package-cluster bootstrap** (resampling packages with replacement, $B = 10,000$) was conducted between Phase 2A and Phase 3:

| Corpus | Target Count | Raw Candidates | Escalations | Point Rate | 95% Cluster Bootstrap CI |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Phase 2A (Benign OSS)** | 180 | 5,020 | 101 | **2.012%** | **[1.062%, 4.681%]** |
| **Phase 3 (Malicious NPM)** | 4,301 | 56,940 | 1,170 | **2.055%** | **[1.758%, 2.366%]** |
| **Cross-Corpus Delta (P3 - P2)** | — | — | — | **+0.043 pp** | **[-2.638 pp, +1.056 pp]** |

### Statistical Implication:
* The 95% bootstrap confidence interval of the cross-corpus difference **includes zero** ($[-2.64\text{ pp}, +1.06\text{ pp}]$).
* **Conclusion:** Observed escalation selectivity was **remarkably stable** across the benign and malicious corpora ($2.01\%$ vs. $2.05\%$, $\Delta = +0.04\text{ pp}$). The orchestrator's filtering funnel is driven by candidate pattern geometry rather than corpus contamination.
