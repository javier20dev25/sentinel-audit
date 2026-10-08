# Sentinel Phase 3 — NPMStudy Malicious Corpus Campaign

**Generated:** 2026-10-08T19:19:39.069Z
**Ground Truth:** ALL packages are MALICIOUS (NPMStudy `zip_malware` corpus)
**Objective:** Recall / True-Positive measurement at scale

---

## Corpus

| Parameter | Value |
|---|---|
| Source | NPMStudy zip_malware |
| Total Targets Scanned | 4301 |
| Ground Truth | MALICIOUS (all) |
| Concurrency | 8 workers |
| Engine Freeze | audit@1.1.0 / cli@ae10c22 / oracle@292123e / cloud@ebc469a |
| Model | google/gemini-3.5-flash-lite @ T=0 |

---

## Verdict Distribution

| Verdict | N | % |
|---|---|---|
| BLOCK | 2956 | 68.73% |
| REVIEW | 215 | 5.00% |
| PASS | 106 | 2.46% |
| TIMEOUT | 0 | 0.00% |
| ERROR / NO_ARTIFACT | 1024 | 23.81% |

---

## Recall Metrics

| Metric | Value |
|---|---|
| **Strict Recall (BLOCK = TP)** | **68.73%** (2956/4301) |
| Detection Rate (BLOCK + REVIEW) | 73.73% (3171/4301) |
| False Negatives (PASS) | 106 (2.46%) |

---

## Engine Signals

| Engine | Raw Alerts |
|---|---|
| Cloud | 32760 |
| CLI | 14219 |
| Oracle | 9961 |
| **Total Raw Candidates** | **56940** |

**Severity Distribution of Raw Candidates:**

| Severity | Count |
|---|---|
| CRITICAL | 5636 |
| HIGH | 7917 |
| MEDIUM | 12679 |
| LOW | 30708 |

---

## Hybrid Triage Funnel

| Stage | Count | Rate |
|---|---|---|
| Raw Candidates | 56940 | 100% baseline |
| Agentic Escalations | 1170 | 2.05% of raw candidates |
| Confirmed via Escalation | 76 | 6.50% yield of escalations |
| Suppressed (not escalated) | 55770 | 97.95% |

**Escalation Selectivity at scale: 2.05%** (raw candidates → agentic escalation)
**Escalation Yield at scale: 6.50%** (escalations → confirmed findings)

---

## Performance

| Metric | Value |
|---|---|
| Avg extraction time | 213.91 ms/pkg |
| Avg Cloud scan time | 1116.46 ms/pkg |
| Avg CLI scan time | 456.21 ms/pkg |
| Avg Oracle scan time | 1417.69 ms/pkg |
| Avg hybrid triage time | 0.55 ms/pkg |
| Avg total wall time | 3209.73 ms/pkg |

---

## Campaign Errors

| Type | Count |
|---|---|
| Campaign errors (fatal per package) | 0 |
| Scan errors (caught) | 6 |
| No artifact | 1018 |
