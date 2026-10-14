# Phase 5: Real-World Vulnerability Benchmark (Pilot N=50)

## Executive Summary & Metrics

Phase 5 evaluates Sentinel's ability to identify real-world CVEs across dual git revisions (vulnerable state vs. patched negative control) using strict, file-attributed scoping.

```text
PHASE 5 — REAL-WORLD VULNERABILITY PILOT (N=50 Pairs / 100 Revisions)
=====================================================================
Total Vulnerability Pairs        50
Total Revisions Scanned         100  (50 vulnerable, 50 patched)
Wall Clock Latency              606.81 s
Execution Model                 Static Analysis Only (Zero target code execution)

VULNERABLE REVISION PERFORMANCE
--------------------------------
Scannable Vulnerable Targets     47  (3 checkout failures: P5-003, P5-006, P5-050)
Attributed True Positives (TP)   21
Attributed False Negatives (FN)  26
File-Attributed Alert Rate    44.68% (21 / 47)

PATCHED REVISION PERFORMANCE (NEGATIVE CONTROL)
-----------------------------------------------
Patched Revisions Scanned        50
Attributed Clean (CLEAN_PATCHED) 26
Attributed Alert (ALERT_PATCHED) 24
Patched Revision Clean Rate      52.00% (26 / 50)
Patched Revision Alert Rate      48.00% (24 / 50)

PAIRED DISCRIMINATION
----------------------
Paired Both Correct (TP + Clean)  0  (0.00%)
Paired Both Alerted              21
Paired Both Clean                25
Paired Inverted (FN + Alert)      1
```

---

## 1. Pilot Acceptance Gates (G1 - G8)

| Gate | Description | Status | Evidence |
|:---|:---|:---:|:---|
| **G1** | Manifest & Ground Truth Complete | **PASS** | 50/50 pairs with GHSA IDs, fix SHAs, parent SHAs, and affected source paths |
| **G2** | Vulnerable Revisions Processed | **PASS** | 50 revisions processed (47 completed, 3 checkout failures) |
| **G3** | Patched Revisions Processed | **PASS** | 50 revisions scanned |
| **G4** | Total Records Recorded | **PASS** | 100 records in `PHASE5_RESULTS.jsonl` |
| **G5** | Arithmetic Reconciliation | **PASS** | Reconciled counts match across severity and CWE breakdowns |
| **G6** | Zero Code Execution | **PASS** | Pure static analysis (worktree checkouts + AST/regex SAST; no lifecycle scripts) |
| **G7** | Engine SHA Frozen | **PASS** | All scanned records bound to frozen engine `012e095b583f6f1c4295eb4feea91456bc9321c2` |
| **G8** | Live Routing & Provenance Logged | **PASS** | 97/97 scanned records exhibit active routing metadata and specialist execution logs |

**Overall Pilot Gate Status:** **PASS**

---

## 2. Technical Adjudication & Limitations

1. **File-Attribution is Not Specific CVE Detection:**
   The apparent 44.68% detection rate (21/47) reflects file-level coexistence, not proven detection of the specific CVE weakness. When inspecting the 21 alleged true positives forensically, Sentinel flags background behavioral sinks present in those files (e.g. `UNSAFE_EVAL` in `underscore.js`, `OS_CAPABILITY` via RegExp execution in `lodash.js`, or comments matching keywords) rather than the logic bug described in the GHSA advisory.
2. **Zero Paired Discrimination (0 / 47 = 0.00%):**
   In 46 out of 47 evaluable pairs, Sentinel produced identical outputs across both revisions:
   - 21 pairs alerted in both revisions (`ALERT_VULN` + `ALERT_PATCHED`)
   - 25 pairs remained clean in both revisions (`CLEAN_VULN` + `CLEAN_PATCHED`)
   - 1 pair inverted (`CLEAN_VULN` + `ALERT_PATCHED`)
   - 0 pairs exhibited the expected discrimination pattern (alert on vulnerable, clean on patch).
3. **Operational Scope:**
   Sentinel SAST was built for behavioral supply-chain analysis (malware indicators, exfiltration, obfuscation) rather than fine-grained logic bug discrimination in established open-source libraries. Expanding to N=200 is halted until semantic triage and vulnerability-specific adjudication rubrics are established.
