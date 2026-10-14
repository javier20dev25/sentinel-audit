# Phase Y2.2 & Ecosystem Isolation Claim Audit

**Date:** 2026-10-10  
**Audit Target:** Repository commit anchors, isolation verification, and claim evidence reconciliation.  

---

## 1. Frozen Repository Commit Verification

A comprehensive audit was performed across all external repositories comprising the Sentinel defensive ecosystem. A simple `git status` inside `sentinel-audit` is insufficient; each repository was queried independently for its current `git rev-parse HEAD` and working tree cleanliness:

| Repository Name | Filesystem Path | Documented Pinned Anchor SHA | Current Measured HEAD SHA | Working Tree Status | Isolation Integrity State |
|---|---|---|---|---|---|
| **sentinel-audit (Core)** | `C:\Users\sleyt\sentinel-audit` | `ea8f667405d91fd281d8ed62b0f03ba3fdb78d0d` | `ea8f667405d91fd281d8ed62b0f03ba3fdb78d0d` | Modified (untracked benchmark dirs) | **ANCHORED (Core)** |
| **sentinel-cli** | `C:\Users\sleyt\sentinel-cli` | `ae10c223db766a041cb8a3dda561485769b47877` | `ae10c223db766a041cb8a3dda561485769b47877` | CLEAN (No uncommitted changes) | **VERIFIED IMMUTABLE** |
| **sentinel-oracle** | `C:\Users\sleyt\sentinel-oracle` | `292123e1e2be22781c0184eb444c1b6be9f1840a` | `292123e1e2be22781c0184eb444c1b6be9f1840a` | CLEAN (No uncommitted changes) | **VERIFIED IMMUTABLE** |
| **sentinel-cloud** | `C:\Users\sleyt\sentinel-cloud` | `ebc469ae9797f269f4cc20c1b322260e97bc0b7a` | `ebc469ae9797f269f4cc20c1b322260e97bc0b7a` | CLEAN (No uncommitted changes) | **VERIFIED IMMUTABLE** |
| **sentinel-ecosystem** | `C:\Users\sleyt\sentinel-ecosystem`| `4f429399f5dcd7a76c37a1582d45686b9ff6f3b1` | `4f429399f5dcd7a76c37a1582d45686b9ff6f3b1` | CLEAN (No uncommitted changes) | **VERIFIED IMMUTABLE** |

### Finding on Isolation (Gate G8):
- Zero commits have been added to `sentinel-cli`, `sentinel-oracle`, `sentinel-cloud`, or `sentinel-ecosystem`.
- All production repositories remain completely clean and identical to their documented commit hashes.
- Sentinel Y v0.1 and v0.2 exist solely inside `C:\Users\sleyt\sentinel-audit\sentinel-y` and have zero import or dependency ties into production Sentinel Cloud or CLI.

---

## 2. Claim vs. Evidence Matrix

Every factual and technical claim made in the Phase Y2.2 and Y3 summaries is cross-referenced below with its verifiable evidence state:

| Claim ID | Claim Statement | Verifiable Evidence | Status | Resolution Condition |
|---|---|---|---|---|
| **CLM-01** | *Sentinel Y v0.2 preserves 100% (4/4) calibration regression.* | Unit test execution on P5-013, P5-015, P5-033, P5-041 produces clean differential signals in `PHASE_Y2_2_RESULTS.jsonl`. | **VERIFIED** | Regression gate G7 satisfied on calibrated sample. |
| **CLM-02** | *CodeQL achieved 18.18% (2/11) on Y3 cohort.* | Ephemeral stdout in Task 4428 showed P5-030 and P5-039 signals, but SARIF files were deleted and not archived. Only 6 pairs have persistent SARIFs. | **CONTRADICTED** | Reconciled: CodeQL verified sample is 0/6 (0.00%); 7 pairs are unmeasured. |
| **CLM-03** | *Sentinel Y achieved 7.69% (1/13) in blind evaluation.* | `json5` (P5-029) was part of Phase Y1 discovery cohort. The evaluation was a retrospective holdout, not an independent blind trial. | **PARTIALLY_VERIFIED** | Reclassified: 1/13 on retrospective holdout, 1/6 on verified common subcorpus. |
| **CLM-04** | *Benign control false positive rate dropped to 20%.* | Confirmed false alarms fell from 3/7 to 2/10 records (2/9 unique packages, 22.2%). However, 2 additional records generate candidate noise (total noise rate = 40.0% / 44.4%). | **PARTIALLY_VERIFIED** | Reconciled: Disclose confirmed FPR (20%) alongside total operational noise rate (40%). |
| **CLM-05** | *Prototype pollution analysis handles receiver semantics and values.* | Implemented heuristic keyword checks; counterexamples show `Document.prototype[fn] = ...` is suppressed without verifying `fn` bounds, and nested boolean writes are flagged as dynamic writes. | **PARTIALLY_VERIFIED** | Reclassified as rule heuristic with documented analysis boundaries, not full abstract interpretation. |
| **CLM-06** | *ReDoS analyzer generalises across grammar families via AST analysis.* | Implemented bounded regex structural checks, but counterexamples show finite repetition under star `(a{0,256})*` and lookaheads `(?=a+)(a+)+` can be bypassed. | **PARTIALLY_VERIFIED** | Reclassified: Broadened beyond literal strings, but bounded heuristics require full NFA state-set analysis. |
| **CLM-07** | *Production Sentinel ecosystem remains strictly isolated (G8).* | Verified HEAD commit SHAs and clean git status across CLI, Oracle, Cloud, and Ecosystem repos. | **VERIFIED** | Full isolation audit confirmed. |
