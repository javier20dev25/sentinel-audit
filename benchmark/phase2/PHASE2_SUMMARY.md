# Sentinel Ecosystem Phase 2 — Real-World Benign OSS Report

**Campaign:** `PHASE2_REAL_WORLD_BENIGN_OSS`
**Execution Timestamp:** 2026-10-08T04:50:57.970Z
**Total Benign Targets Evaluated:** 180

---

## 1. Executive Summary & Verdict Distribution

| Verdict | Count | Percentage | Interpretation |
| :--- | :---: | :---: | :--- |
| **PASS** | **102** | **56.67%** | Clean / low-risk benign software |
| **REVIEW** | **67** | **37.22%** | Uncorroborated single-lens observations / heuristics |
| **BLOCK (False Alarm)** | **11** | **6.11%** | False alarm rate under Sentinel Audit orchestration |

> **Key Research Finding:** Under raw Sentinel Cloud, benign npm packages previously experienced up to **84.4% HIGH+ FPR**. Under Sentinel Audit's orchestrated Hybrid Triage pipeline, false BLOCK decisions drop to **6.11%**. The remaining uncorroborated alerts are channeled into non-blocking **REVIEW**, preserving developer velocity while preventing false alarms.

---

## 2. Hybrid Triage & Escalation Dynamics

- **Total Candidates Evaluated:** 5020
- **Agentic Escalations:** 101
- **Total Tool Calls:** 101
- **Escalation Selectivity:** **2.01%** (only ambiguous sinks trigger tool escalation)
- **Escalation Yield:** **26.73%**
- **False Positives Dismissed via Dataflow:** 4897

---

## 3. Raw Engine Activity Comparison

| Engine | Total Alerts | Avg Alerts / Target | Median Latency (ms) | p95 Latency (ms) |
| :--- | :---: | :---: | :---: | :---: |
| **Sentinel Cloud** | 4115 | 22.86 | 130.57 | 6091.34 |
| **Sentinel CLI** | 470 | 2.61 | 42.85 | 1500.87 |
| **Sentinel Oracle** | 435 | 2.42 | 142.05 | 2239.22 |

---

## 4. Environment & Immutable Freeze Anchor

- **Ecosystem Freeze SHA:** `fee04e16f428369ecfb421c82d6420f9d3b7801d`
- **Audit Version / SHA:** `1.1.0` / `012e095bc362129253435328e246c4f901e7842d`
- **CLI Engine SHA:** `ae10c223db766a041cb8a3dda561485769b47877`
- **Oracle Engine SHA:** `292123e1e2be22781c0184eb444c1b6be9f1840a`
- **Model / Temperature:** `google/gemini-3.5-flash-lite` (T=0)
- **Node.js:** `v24.13.1` on `win32 (x64)`
