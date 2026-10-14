# Phase Y1: Reference Campaign Summary & Empirical Findings

## 1. Executive Summary

Phase Y1-B executed a complete, static-only reference tool campaign over the **26 Phase 5 missed-vulnerability cases** (52 snapshots across vulnerable and patched git revisions).

Tools evaluated under pinned, frozen configurations:
- **CodeQL CLI 2.27.1** (`security-extended` suite, `javascript-queries@2.4.6`)
- **Semgrep OSS 1.175.0** (`p/javascript` ruleset)

```text
PHASE Y1-B — REFERENCE CAMPAIGN METRICS (N=26 Cases / 52 Snapshots)
===================================================================
Total Discovery Cases            26
Total Source Snapshots Analyzed  52  (26 vulnerable, 26 patched)
Execution Model                 Pure Static Analysis (No target code execution)

SEMGREP OSS (p/javascript)
--------------------------
In-Scope Vulnerable Alerts        0  (0.00%)
In-Scope Patched Alerts           0  (0.00%)
Paired Discriminations            0  (0.00%)

CODEQL (security-extended)
--------------------------
In-Scope Vulnerable Alerts        9  (34.62%)
In-Scope Patched Alerts           5  (19.23%)
Paired Discriminations (V->Alert, P->Clean): 4 (15.38%)

SEMANTIC ADJUDICATION (26 Cases)
--------------------------------
REFERENCE_DETECTED_CVE_SPECIFIC   4  (15.38%) [P5-013, P5-015, P5-033, P5-041]
REFERENCE_DETECTED_RELATED        3  (11.54%) [P5-014, P5-016, P5-031]
UNRELATED_SECURITY_ALERT          2  (7.69%)  [P5-011, P5-042]
NO_REFERENCE_DETECTION           17  (65.38%)
```

---

## 2. Key Takeaways for Sentinel Y Engineering

1. **Semgrep OSS is Ineffective on Complex Logic Flaws:**
   A simple syntactic AST matcher with generic community rules caught 0 of the 26 library vulnerabilities. Building Sentinel Y cannot rely on shallow pattern matching.
2. **CodeQL Detections Are Driven by Specific Invariant Models:**
   CodeQL succeeded specifically on two analytic classes:
   - **Prototype Pollution Utility Analysis (`js/prototype-pollution-utility`)**: Tracks recursive key-assignment loops and verifies whether a guard `if (key === '__proto__')` dominates the assignment node.
   - **Polynomial ReDoS (`js/polynomial-redos`)**: Computes NFA ambiguity on regular expression ASTs and tracks untrusted string flows into regex match calls.
3. **Reference Tool Gaps (65.4% Undetected):**
   Even CodeQL `security-extended` missed 17 of the 26 CVEs (e.g. `sequelize` SQL injection through custom query generators, `moment` timezone path traversal, `xmldom` recursive expansion). These require domain-specific structural or semantic models rather than generic interprocedural taint.

---

## 3. Next Steps for Sentinel Y Prototype

With empirical proof in hand, the development of Sentinel Y will begin with an isolated prototype targeting the two mathematically validated mechanisms:
1. `Y-PROTO-001`: Prototype pollution key-guard dominance analyzer.
2. `Y-REDOS-001`: Regular expression NFA ambiguity analyzer.
