# Prospective Benchmark Gate Checklist V1

**Benchmark Phase:** Prospective Independent Evaluation (N=100 Pairs + N=100 Controls)  
**Governance Checklist:** Pre-Execution, Execution, and Post-Execution Audit Verification  
**Current Governance State:** `PROTOCOL_COMMITTED` (Specifications Drafted & Committed; Sealing & Custody Pending)  

---

## Pre-Execution Gates (Must Be 100% Satisfied Prior to Corpus Exposure)

- [ ] **Gate PRE-1 (Engine Decision & Freeze):** Formal decision whether benchmark target is v0.2.0 (as research baseline) or v0.3.0 (after fixing counterexamples CE-02/CE-04/CE-05). Target engine SHA-256 hash computed, committed, and frozen.
- [ ] **Gate PRE-2 (Independent Custodian Appointment):** Independent entity appointed with exclusive authority over manifest generation and ground truth retention.
- [ ] **Gate PRE-3 (Corpus Separation Verification):** Custodian formally verifies that 100% of candidate packages are absent from Phase 5, Phase Y1, Phase Y2, and Phase Y3 holdouts.
- [ ] **Gate PRE-4 (Adversarial Hard Controls Sealed):** Exactly 100 negative controls selected, featuring superficial similarities to prototype and ReDoS sinks.
- [ ] **Gate PRE-5 (De-identification & Sanitization):** Manifest and source snapshots sanitized of identifying metadata (`package.json`, READMEs, git remote URLs, comment headers).
- [ ] **Gate PRE-6 (Opaque Identifier Assignment):** All package names and repo URLs converted to opaque IDs (`CASE-XXXX-XXXX`). Manifest encrypted and sealed under custodian custody.
- [ ] **Gate PRE-7 (Baseline Parity Contract):** Reference engine (CodeQL 2.27.1) and Sentinel Y runner configured with identical timeout (180s) and memory constraints (4 GB).

---

## Execution Gates (Run-Time Invariants)

- [ ] **Gate RUN-1 (Zero Dynamic Execution):** Prohibit `npm install`, build steps, or dynamic test commands. Only static git worktree checkouts permitted.
- [ ] **Gate RUN-2 (Strict Status Verification):** The runner records explicit return codes. Missing output files trigger `EXECUTION_FAILED`, never defaulting to 0 findings.
- [ ] **Gate RUN-3 (Immutable Snapshot Persistence):** All raw output SARIF and JSONL files saved to permanent disk storage before any metric computation.

---

## Post-Execution Gates (Adjudication & Acceptance)

- [ ] **Gate POST-1 (Sample Completeness):** At least 90 pairs must have successful, fully measured runs for both engines to establish a valid comparison.
- [ ] **Gate POST-2 (Double-Blind Adjudication):** Two independent human reviewers evaluate all differential signals against commit diffs per `CVE_ADJUDICATION_RUBRIC_V1.md` using engine-masked outputs.
- [ ] **Gate POST-3 (Common Denominator Enforcement):** All comparative head-to-head metrics reported over the exact common subset of measured pairs.
- [ ] **Gate POST-4 (Statistical Significance Test):** Superiority claims require McNemar's paired test with $p < 0.05$.
- [ ] **Gate POST-5 (Blinding Integrity Verification):** If any team member inspected prospective package identities or adjusted rules during the run, the entire benchmark is formally invalidated and labeled an unblinded calibration run.
