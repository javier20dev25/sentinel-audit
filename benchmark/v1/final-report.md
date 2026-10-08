# Sentinel Benchmark v1 — Final Technical Report

**Benchmark Classification:** `CONTROLLED_BENCHMARK_RESULT`  
**Statistical Quality:** `LOW_MEDIUM_CONTROLLED_ENGINEERING_STUDY`  
**Dataset Scope:** N=28 frozen cases (7 malicious, 21 benign)  
**Evaluated Model:** `google/gemini-3.5-flash-lite`, temperature = 0.0  
**Measurement Integrity:** `ACTUAL_TOKEN_MEASUREMENT = PASS` (native provider usageMetadata)  

---

## 1. Summary of Comparative Results

| Metric | AI_ALONE | SENTINEL_ASSISTED | SENTINEL_AGENTIC (Pure) | SENTINEL_HYBRID (Final) |
| :--- | :---: | :---: | :---: | :---: |
| **Total Cases** | 28 | 28 | 28 | **28** |
| **Decided Cases** | 11 | 28 | 18 | **28** |
| **Abstentions (UNKNOWN)** | 17 | 0 | 10 | **0** |
| **Coverage** | 39.3% (11/28) | 100.0% (28/28) | 64.3% (18/28) | **100.0% (28/28)** |
| **TP (out of 7)** | 6 | 7 | 3 | **7** |
| **TN (out of 21)** | 4 | 20 | 15 | **21** |
| **FP** | 1 | 1 | 0 | **0** |
| **FN** | 0 | 0 | 0 | **0** |
| **Decision Accuracy** | 90.9% (10/11) | 96.4% (27/28) | 100.0% (18/18) | **100.0% (28/28)** |
| **Precision (among decisions)** | 85.7% (6/7) | 87.5% (7/8) | 100.0% (3/3) | **100.0% (7/7)** |
| **Recall (global over 7 GT)** | 85.7% (6/7) | 100.0% (7/7) | 42.9% (3/7) | **100.0% (7/7)** |
| **Conventional FPR** | 20.0% (1/5) | 4.8% (1/21) | 0.0% (0/15) | **0.0% (0/21)** |
| **False Alarm Incidence (all benign)** | 4.8% (1/21) | 4.8% (1/21) | 0.0% (0/21) | **0.0% (0/21)** |
| **Tool Calls** | 0 | 0 | 16 | **2** |
| **Tool Call Reduction** | — | — | Baseline (16) | **87.5% reduction** |
| **Sum Case Runtime** | 145.8s | 144.9s | 69.2s | **134.7s** |
| **Campaign Wall-Clock Time** | — | — | — | **188.9s** |
| **Total Tokens** | 13,321 | 18,979 | 22,390 | **20,696** |
| **Tokens per Correct Decision** | 1,332.1 | 702.9 | 1,243.9 | **739.1** |

---

## 2. Validation of Hybrid Escalation & Tool Calls

The Hybrid pipeline executed only **2 tool calls** across the entire 28-case evaluation (an observed tool call reduction of **87.5%** compared to Agentic Pure):

1. **`SP01a` (`eval(constante)`):**
   - *Escalation Reason:* Static heuristic flagged `eval()` as dangerous (`UNSAFE_EVAL`).
   - *Tool Invocation:* Escalated to Agentic. Model inspected AST/literal scope without invoking secondary tools.
   - *Veredict:* `BENIGN` (TN ✅). Falso positivo eliminado.
2. **`SP01b` (`eval(userInput)`):**
   - *Escalation Reason:* Static heuristic flagged `eval()` with taint flow from `req.body.code`.
   - *Tool Invocation:* Invoked `inspect_source snippet.js` and `inspect_dataflow snippet.js 1 eval`.
   - *Veredict:* `CONFIRMED` (TP ✅). Taint reach comprobado formalmente.

---

## 3. Disproof of Early Estimation
The preliminary speculative estimate of `~140,000 input / ~4,000 output tokens` is **formally rejected**. Actual native provider usage metadata yielded:
- **`AI_ALONE`:** 13,321 tokens
- **`SENTINEL_ASSISTED`:** 18,979 tokens
- **`SENTINEL_AGENTIC`:** 22,390 tokens
- **`SENTINEL_HYBRID`:** 20,696 tokens

Sentinel Assisted and Hybrid provide a **nearly 2x improvement in token efficiency per correct decision** (~703–739 tokens/decision) compared to unassisted LLM reasoning (~1,332 tokens/decision).
