# Phase Y1 Validation & Blind-Split Evaluation Plan

## 1. Principles of Evaluation Integrity

To prevent overfitting to the Phase 5 discovery cohort, the development and evaluation of Sentinel Y must adhere to strict data-split rules:

1. **Discovery Cohort (Development Set):** The 26 missed detections + 21 unspecific alerts from Phase 5 are used exclusively for mechanism extraction, AST rule design, and prototype debugging.
2. **Blind Validation Cohort (Unseen Test Set):** Sentinel Y will be evaluated against a newly curated, disjoint benchmark of real-world vulnerabilities ($N \ge 100$ pairs) from distinct packages never seen during discovery.
3. **Paired Test Requirement:** Every target in the blind test set MUST be evaluated in paired revisions (vulnerable vs patched negative control).
4. **Negative Controls (Benign OSS):** Include 100 top clean npm libraries to evaluate false-positive rate (FPR).

---

## 2. Experimental Milestones

| Milestone | Target | Description | Success Metric |
|:---|:---:|:---|:---|
| **Y0** | Discovery | Reverse-engineer mechanisms from Phase 5 misses | Specifications documented (G1–G7 PASS) |
| **Y1** | Prototype | Implement standalone Prototype Pollution (`Y-PROTO`) & ReDoS (`Y-REDOS`) detectors | 100% paired discrimination on discovery unit tests |
| **Y2** | Blind Evaluation | Test on $N=50$ unseen external CVE pairs | Paired discrimination $\ge 70\%$, FPR on benign $\le 5\%$ |
| **Y3** | Shadow Cloud Integration | Deploy in shadow mode inside Sentinel Cloud | Correlated verdicts without regressions |
