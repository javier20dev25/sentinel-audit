# Sentinel AI Benchmark v1 — Results

**Completed:** 2026-10-07T17:06:07.965Z
**Model:** google/gemini-3.5-flash-lite temp=0
**Statistical Quality:** LOW_MEDIUM_CONTROLLED_ENGINEERING_STUDY
**Corpus:** 6 malicious + 20 benign + 2 semantic pair = 28 cases

## Results by Mode

| Metric | AI_ALONE | SENTINEL_ASSISTED | SENTINEL_AGENTIC |
| :--- | ---: | ---: | ---: |
| TP | 6 | 7 | 3 |
| TN | 4 | 20 | 15 |
| FP | 1 | 1 | 0 |
| FN | 0 | 0 | 0 |
| UNKNOWN | 17 | 0 | 10 |
| Precision | 85.7% | 87.5% | 100.0% |
| Recall | 100.0% | 100.0% | 100.0% |
| FPR | 20.0% | 4.8% | 0.0% |
| FNR | 0.0% | 0.0% | 0.0% |
| Total Tokens | 13321 | 18979 | 22390 |
| Avg Tokens/run | 476 | 678 | 800 |
| Wall Time (ms) | 145812 | 144861 | 69173 |
| Tool Calls | 0 | 0 | 16 |
| Confirmed/1k tokens | 0.4504 | 0.3688 | 0.134 |
| Token Measurement | PASS | PASS | PASS |

## Semantic Pair Results

| Case | Mode | Ground Truth | AI Verdict | Correct? |
| :--- | :--- | :--- | :--- | :--- |
| SP01a | AI_ALONE | BENIGN | CONFIRMED | ❌ |
| SP01a | SENTINEL_ASSISTED | BENIGN | CONFIRMED | ❌ |
| SP01a | SENTINEL_AGENTIC | BENIGN | BENIGN | ✅ |
| SP01b | AI_ALONE | MALICIOUS | CONFIRMED | ✅ |
| SP01b | SENTINEL_ASSISTED | MALICIOUS | CONFIRMED | ✅ |
| SP01b | SENTINEL_AGENTIC | MALICIOUS | UNKNOWN | ❌ |

## Benchmark Status

```
BENCHMARK_COMPLETE = YES
ACTUAL_TOKEN_MEASUREMENT = PASS
```
