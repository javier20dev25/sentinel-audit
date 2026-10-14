# Sentinel Y — Prospective Benchmark Protocol V1 (N=100 Pairs + N=100 Controls)

**Document Version:** 1.0.0-PROSPECTIVE  
**Governance:** Independent Blinding & Sealed Custody Protocol  
**Target Evaluation Scope:** 100 Verified Vulnerability Pairs + 100 Hard Negative Controls  
**Status:** SEALED PRIOR TO CORPUS SELECTION (No engine modification permitted after sealing)  

---

## 1. Core Principles & Blinding Contract

1. **Complete Separation of Roles:**
   - **Corpus Custodian (Independent):** Selects targets, verifies git commits, generates opaque IDs (`CASE-XXXX-XXXX`), hashes ground truth diffs, and holds the unblinding key.
   - **Engine Implementer:** Maintains the detection engine (`sentinel-y`). Has zero access to candidate package names, repository URLs, or CVE IDs prior to execution.
   - **Adjudication Panel (2 Reviewers):** Evaluates finding traces against diffs without knowing which engine generated each trace.
2. **Disjointness Invariant:**
   - The prospective corpus must be **100% package-disjoint and repository-disjoint** from Phase 5 (all 50 packages), Phase Y1 (26 discovery packages), Phase Y2 (4 calibration packages), and Phase Y3 holdouts.
3. **No Dynamic Code Execution:**
   - Evaluated exclusively via static AST traversal. Zero execution of `npm install`, lifecycle scripts, builds, or exploits.

---

## 2. Corpus Stratification & Eligibility Rules

The prospective corpus consists of **200 total cases**:

### 2.1 Vulnerability Pairs (N = 100 Paired Snapshots)
- **Panel A: Prototype Pollution (N = 50 Pairs):**
  * Sub-family A1 (Recursive Property Mergers): 20 pairs.
  * Sub-family A2 (Dynamic Property Writes / Setters): 15 pairs.
  * Sub-family A3 (Path-based Object Setters): 10 pairs.
  * Sub-family A4 (Unfiltered Object.assign / Spread Traversal): 5 pairs.
- **Panel B: Regular Expression Denial of Service (N = 50 Pairs):**
  * Sub-family B1 (Nested Repetitive Quantifiers): 20 pairs.
  * Sub-family B2 (Overlapping Alternations under Repetition): 15 pairs.
  * Sub-family B3 (Adjacent Overlapping Quantifiers): 10 pairs.
  * Sub-family B4 (Unanchored Greedy Prefix Backtracking): 5 pairs.

#### Eligibility Criteria for Vulnerability Pairs:
1. Public GHSA and CVE published between 2017 and 2026.
2. Identifiable, reproducible vulnerable git commit SHA and remediation commit SHA in an active public repository.
3. Patch diff cleanly attributes the fix to the reported weakness without major unrelated refactors.
4. Target source file is pure JavaScript/TypeScript.

### 2.2 Benign Hard Negative Controls (N = 100 Snapshots)
- Must feature syntactical patterns superficially resembling vulnerability sinks:
  * Shallow dictionary options copies (`target[k] = opts[k]`).
  * Schema validator property assignments.
  * Complex regular expressions with lookaheads, bounded quantifiers `{1,64}`, or atomic groupings.
  * Flat array loops with numeric index indexing.

---

## 3. Operational Runner Contract & Resource Limits

- **Timeout:** 180 seconds per snapshot.
- **Memory Limit:** 4 GB Node.js heap limit (`--max-old-space-size=4096`).
- **Error Handling Policy:**
  * If the parser crashes: status = `PARSER_CRASH`.
  * If the execution times out: status = `TIMEOUT`.
  * If an unhandled exception occurs: status = `EXECUTION_FAILURE`.
  * **Under zero circumstances may an execution error default to 0 findings or be classified as `NO_ALERT`.**

---

## 4. Pre-Registered Metrics & Acceptance Thresholds

Every metric is defined mathematically with mandatory common denominators:

1. **Paired Patch Discrimination Rate ($PDR$):**
   $$PDR = \frac{\sum_{i=1}^{N_{measured}} [Alert(V_i) \land \neg Alert(P_i)]}{N_{measured}}$$
2. **CVE-Specific Discrimination Rate ($CSDR$):**
   $$CSDR = \frac{\sum_{i=1}^{N_{measured}} [Alert_{specific}(V_i) \land \neg Alert(P_i)]}{N_{measured}}$$
3. **Persistent Alert Rate ($PAR$):**
   $$PAR = \frac{\sum_{i=1}^{N_{measured}} [Alert(V_i) \land Alert(P_i)]}{N_{measured}}$$
4. **Hard Negative Control Specificity ($TNR_{ctrl}$):**
   $$TNR_{ctrl} = \frac{\sum_{j=1}^{N_{ctrl}} [\neg Alert_{confirmed}(C_j)]}{N_{ctrl}}$$
5. **Candidate Noise Rate ($CNR_{ctrl}$):**
   $$CNR_{ctrl} = \frac{\sum_{j=1}^{N_{ctrl}} [Alert_{candidate}(C_j)]}{N_{ctrl}}$$

### Pre-Registered Acceptance Thresholds (Before Corpus Execution):
- **Minimum Target Sample:** At least 90 of 100 pairs must be fully measured without timeouts.
- **Superiority Criterion:** Sentinel Y can only claim superior paired discrimination over CodeQL if:
  $$CSDR_{SentinelY} - CSDR_{CodeQL} \ge 10.0\% \quad (p < 0.05 \text{ via McNemar's test on paired data})$$
- **Specificity Gate:** Confirmed false alarm rate on controls must not exceed $15.0\%$. Total candidate noise rate must not exceed $30.0\%$.
