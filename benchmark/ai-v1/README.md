# Sentinel AI Benchmark v1

## Purpose
Measure empirically how much deterministic work Sentinel performs *before* an LLM needs to reason, and how that reduces tokens and time needed to reach confirmed findings.

## Research Question
> Can Sentinel filter, correlate, and generate evidence such that an AI working on Sentinel output uses fewer tokens and less time than an AI working from raw code alone, while maintaining or improving recall?

## Frozen Dataset
- **Corpus:** 26 cases (6 malicious + 20 benign) + 2 semantic pair variants = 28 evaluation units
- **Target A:** `merx @ 201a949` (full repo, 61 files)
- **Target B:** PR #12 (`b70c277` over base `201a949`) — 3 adversarial files: `scripts/health-check.js`, `scripts/report-utils.js`, `package.json`
- **Target C:** `sentinel-cloud-client @ 924d25d` (benign control)
- **Statistical quality:** `LOW/MEDIUM` — controlled engineering study, N=28

## Three Modes

### Mode A — AI_ALONE
- AI sees: code/diff only
- AI cannot: execute code, run tools, access Sentinel findings, access internet

### Mode B — SENTINEL_ASSISTED
- AI sees: Sentinel CLI + Cloud normalized findings + promoted files + evidence
- AI cannot: run new scanners, execute code
- AI must: resolve each candidate using only provided evidence

### Mode C — SENTINEL_AGENTIC
- AI starts with: Sentinel Audit expediente
- AI may: request deterministic tool outputs (inspect_source, run_semgrep, run_codeql, etc.)
- AI decides: WHEN to request more evidence
- `run_tests_if_safe` is DISABLED (untrusted target)

## Ground Truth Rules
- Ground truth is **never revealed to the model** during evaluation
- Ground truth is fixed in `ground-truth.js`
- Model output is scored: `TP / TN / FP / FN / UNKNOWN`
- Ground truth is **never modified** to accommodate model errors

## Model Configuration
- Provider: Anthropic
- Model: claude-sonnet-4-5
- Temperature: 0 (deterministic as possible)
- Same model, same config, all three modes

## Token Measurement
- Real usage from Anthropic API `usage` field
- `inputTokens`, `outputTokens`, `cachedInputTokens`, `totalTokens`
- If API not available: `ACTUAL_TOKEN_MEASUREMENT = UNAVAILABLE`
- Previous estimate `~140k input / ~4k output` tagged as `AI_EQUIVALENT_TOKEN_ESTIMATE` only

## Files
| File | Description |
|------|-------------|
| `ground-truth.js` | Frozen ground truth registry — never in prompts |
| `cases.js` | Case definitions with mode-specific input payloads |
| `prompts.js` | Versioned system + task prompt builders |
| `parser.js` | AI response parser + scorer |
| `runner.js` | Wave executor (max 8 workers) — calls Anthropic API |
| `export.js` | CSV + markdown summary generator |
| `runs.jsonl` | One line per run (appended incrementally) |
| `judgments.jsonl` | Full parsed judgments with raw responses |
| `summary.json` | Final aggregated summary |
| `comparison.csv` | Side-by-side comparison table |
| `summary.md` | Human-readable results |

## Constraints
- NO modifications to CLI, Oracle, Cloud, or Audit during this phase
- NO tuning of scanner rules as reaction to AI results
- NO new scanner rounds after obtaining AI results
- `STATISTICAL_QUALITY = LOW_MEDIUM_CONTROLLED_ENGINEERING_STUDY`
