# Sentinel Benchmark v1 — Methodology & Controlled Evaluation Protocol

## 1. Classification & Scope
- **Benchmark Type:** `CONTROLLED_BENCHMARK_RESULT`.
- **Statistical Quality:** `LOW_MEDIUM_CONTROLLED_ENGINEERING_STUDY`.
- **Purpose:** Measure how much deterministic analysis (Sentinel CLI, Cloud, Audit) can filter and corroborate before LLM reasoning is required, comparing standalone LLM reasoning against assisted and hybrid pipelines.
- **Frozen Commit:** `a91b61f552d9238c5ed3f33de72ac3bf62140bc7`.

---

## 2. Dataset Definition (N=28)
- **Malicious Ground Truth (7 cases):**
  - Vectors V1–V6 from PR #12 on `merx` (`b70c277` over `201a949`):
    - `M01`: C2 Beacon to `telemetry-analytics.xyz` (`health-check.js`).
    - `M02`: Staged remote shell script download + exec (`health-check.js`).
    - `M03`: Unsafe `eval(stdout)` of remote payload (`health-check.js`).
    - `M04`: Credential harvesting & exfiltration (`report-utils.js`).
    - `M05`: Command injection via base64 pipeline (`report-utils.js`).
    - `M06`: Malicious package.json lifecycle scripts (`prestart`, `postinstall`).
  - Semantic variant:
    - `SP01b`: Dynamic `eval(userCode)` with open taint from `req.body.code`.
- **Benign Ground Truth (21 cases):**
  - `B01–B20`: 20 clean synthetic controls (Axios GET/POST, config reads, cache writes, git rev-parse, node -v, env reads, CI workflows, build scripts, mock servers).
  - Semantic variant:
    - `SP01a`: `eval(TEMPLATE)` with closed static constant string.

---

## 3. Strict Metric Formulations
To avoid inflating recall or deflating FPR when abstentions (`UNKNOWN`) occur, the following standard formulas are enforced:

1. **Coverage:**
   $$\text{Coverage} = \frac{\text{Decided Cases}}{\text{Total Cases (28)}} = \frac{TP + TN + FP + FN}{28}$$
2. **Decision Accuracy:**
   $$\text{Decision Accuracy} = \frac{TP + TN}{\text{Decided Cases}}$$
3. **Precision (Among Decisions):**
   $$\text{Precision} = \frac{TP}{TP + FP}$$
4. **Recall (Global over 7 GT positives):**
   $$\text{Recall}_{\text{global}} = \frac{TP}{\text{Total Malicious GT (7)}}$$
5. **Conventional FPR (over resolved benign cases):**
   $$\text{FPR} = \frac{FP}{FP + TN}$$
6. **False Alarm Incidence (over all 21 benign cases):**
   $$\text{Incidence} = \frac{FP}{21}$$

---

## 4. Execution Modes Compared
1. **`AI_ALONE`**: Model receives code/diff in isolation. No access to tools, internet, or scanner outputs.
2. **`SENTINEL_ASSISTED`**: Model receives Sentinel Audit expediente (normalized Cloud/CLI findings, candidate signals, evidence trace). Resolves findings in a single pass.
3. **`SENTINEL_AGENTIC (Pure)`**: Model receives expediente and can iteratively request deterministic tool outputs (`inspect_source`, `inspect_dataflow`, `run_semgrep`).
4. **`SENTINEL_HYBRID` (Architectural Recommendation):**
   - Tier 1: Sentinel deterministic scan + Assisted AI triage.
   - Tier 2 (Escalation): If finding is ambiguous (e.g. dataflow/taint uncertainty) or UNKNOWN, escalate to Agentic tool loop.
