# Phase 5 Final Forensic Audit Report (N=50 Pairs / 100 Revisions)

## 1. Executive Summary

This final audit formally closes Phase 5 without modifying frozen engines, without rerunning scans, and without overwriting original raw records (`PHASE5_RESULTS.jsonl`, `PHASE5_METRICS.json`).

| Metric | Measured Value | Definitive Interpretation |
|:---|:---:|:---|
| Total Target Pairs | 50 | 50 unique GHSA records across 34 distinct npm packages |
| Scannable Pairs Evaluated | 47 | 3 operational checkout exclusions (`P5-003`, `P5-006`, `P5-050`) |
| **File-Attributed Alert Rate (Vuln)** | **21 / 47 (44.68%)** | Alerts coexisting in affected source files; **0% proven CVE-defect recall** |
| Patched Revisions Alert Rate | 24 / 50 (48.00%) | Negative control alert rate on target files |
| Patched Revisions Clean Rate | 26 / 50 (52.00%) | Files without attributed findings post-patch |
| **Paired Patch Discrimination Rate** | **0 / 47 (0.00%)** | 0 pairs satisfied the detection pattern (alert on vulnerable + clean on patch) |
| Binary Classification Agreement | 46 / 47 (97.87%) | Tool verdict matches across revisions (21 both alerted, 25 both clean) |
| Inverted Pairs | 1 / 47 (2.13%) | Vulnerable clean, patch alerted |
| Specific CVE Weakness Detections | 0 / 21 (0.00%) | Forensic adjudication classified all 21 apparent TPs as `UNRELATED_SECURITY_ALERT` |

---

## 2. Task A — Forensic Adjudication of the 21 Apparent True Positives

Forensic adjudication of every single attributed finding revealed that **none of the 21 alerts targeted the specific vulnerability mechanism described in the advisory**:

- **Summary of 21 Cases**:
  - `CVE_SPECIFIC_DETECTION`: **0** (0.00%)
  - `UNRELATED_SECURITY_ALERT`: **21** (100.00%)
  - `OUT_OF_SCOPE`: **0**
  - `AMBIGUOUS`: **0**
- **Mechanism Breakdown**:
  1. **Template Injection (CWE-94)** (e.g. `underscore`, `ejs`): Flagged legitimate `new Function(...)` compilation logic (`SAST-EVAL`) resident in the file before and after the patch. The CVE bug was unescaped variable interpolation in the parser.
  2. **Prototype Pollution (CWE-1321)** (e.g. `mongoose`): Flagged background object traversal sinks, not the absence of prototype key sanitization (`__proto__`, `constructor`).
  3. **Command / Argument Injection (CWE-77, CWE-88)** (e.g. `lodash`, `nodemailer`): Flagged `RegExp#exec` or standard child process APIs in the codebase, persisting identically in patched versions.
  4. **ReDoS (CWE-1333)** (e.g. `semver`, `debug`): Flagged regular expression usage; no regex polynomial automata complexity analysis was performed.

---

## 3. Task B — Complete Paired Matrix Audit

- Total Pairs: 50
- Complete Pairs Scanned: 47
- Incomplete Pairs (Checkout Failures): 3
- Paired Patterns:
  - `BOTH_ALERTED`: 21 (44.68%)
  - `BOTH_CLEAN`: 25 (53.19%)
  - `INVERTED`: 1 (2.13%)
  - `DISCRIMINATED_CORRECT`: 0 (0.00%)
- **`PAIRED_PATCH_DISCRIMINATION_RATE`**: **0.00%** (0 / 47)
- **Binary Classification Agreement**: **97.87%** (46 / 47)

---

## 4. Task C — Provenance and Engine Integrity

- Evaluated engine binary: `sentinel.cmd scan <target> --json` (Sentinel CLI SAST engine, commit `ae10c223db766a041cb8a3dda561485769b47877`).
- Core orchestrator revision: `012e095b583f6f1c4295eb4feea91456bc9321c2` (clean tree).
- Live routing metadata: recorded for 97 scanned records; AI escalation was strictly disabled.
- Zero target code execution observed across all 100 targets.

---

## 5. Architectural Conclusion: The Need for Sentinel Y

The Phase 5 pilot proves that **file-level presence matching overestimates detection capacity**:
1. Sentinel CLI's behavioral rules detect high-risk APIs, not defect invariants.
2. Expanding Phase 5 to N=200 under current rules is formally **HALTED**.
3. To address logic bugs, prototype pollution, ReDoS, and taint paths, an independent semantic analysis engine (**Sentinel Y**) is required, designed with dataflow and security invariant models without modifying the frozen Sentinel X/CLI baseline.
