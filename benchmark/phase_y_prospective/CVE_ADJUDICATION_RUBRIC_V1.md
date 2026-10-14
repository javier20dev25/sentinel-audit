# CVE-Specific Forensic Adjudication Rubric V1

**Version:** 1.0.0  
**Methodology:** Double-Blind Expert Review (2 Independent Reviewers + Arbiter)  

---

## 1. Objective & Adjudication Pipeline

An automated finding that appears in a vulnerable snapshot and disappears in a patched snapshot is initially classified as a **Differential Signal**. To prevent crediting serendipitous or unrelated alerts, every candidate differential signal must pass the **CVE-Specific Adjudication Rubric**.

```
                       [Differential Signal Detected]
                      (Alert on Vuln && No Alert on Patch)
                                     │
                 Reviewer 1 evaluates     Reviewer 2 evaluates
                 independently            independently
                         ╲                 ╱
                          ╲               ╱
                       Do both reviewers agree?
                                 ╱ ╲
                               YES  NO
                               ╱     ╲
                     [Final Veredict] [Arbiter Review & Resolution]
```

---

## 2. Definitive Classification Taxonomy

| Class Code | Category Name | Definition & Evidence Standard |
|---|---|---|
| **CS-CONF** | `CVE_SPECIFIC_CONFIRMED` | The finding's sink location, key variable, or regex subpattern directly matches the line(s) modified by the vulnerability patch, and the alert rule corresponds to the primary CVE vulnerability mechanism. |
| **DIFF-UNREL** | `DIFFERENTIAL_UNRELATED` | The alert disappeared in the patched revision due to general file refactoring or incidental line removal, but did NOT track the vulnerability fix described in the advisory. |
| **PERSIST** | `PERSISTENT_ALERT` | The alert fired on both vulnerable and patched revisions (identical line or identical syntax in patched file). |
| **NO-ALERT** | `NO_ALERT` | The engine produced zero findings on both revisions. |
| **INVERT** | `INVERTED_ALERT` | The engine produced zero findings on the vulnerable revision, but alerted on the patched revision. |
| **EXEC-FAIL** | `EXECUTION_FAILED` | Engine crashed, timed out, or produced an invalid SARIF/JSON. |

---

## 3. Reviewer Checklist & Scoring Rubric

To score a finding as `CVE_SPECIFIC_CONFIRMED`, the reviewer must confirm all four of the following criteria:

1. **Location Alignment:** Does the sink location (file and line $\pm 5$ lines) overlap directly with the lines modified in the remediation commit diff?
2. **Mechanism Correspondence:** Does the finding's `ruleId` (`Y-PROTO-001` or `Y-REDOS-001`) correspond to the CWE identified in the advisory?
3. **Patch Cause Alignment:** Did the patch remediate the vulnerability by altering the construct flagged by the engine (e.g., adding a key validator, bounding a quantifier, replacing `[key]` with `Object.defineProperty`)?
4. **Non-Collateral Signal:** Is the disappearance of the alert explained directly by the fix, rather than by module deletion, variable renaming, or unrelated refactoring?

### Disagreement Resolution:
- If Reviewer 1 and Reviewer 2 assign different categories, the finding is escalated to the **Lead Security Arbiter**.
- The Arbiter inspects the commit log, dataflow traces, and external CVE write-ups, providing a binding written justification.
