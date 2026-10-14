# Sentinel Y Architecture & Engine Specification (Phase Y1)

## 1. Engine Identity & Independence

- **Engine Name:** Sentinel Y (Semantic Vulnerability Analyzer)
- **Target Subsystem:** Sentinel Cloud / Deep Analysis (Standalone Module)
- **Isolation Guarantee:** Zero runtime dependency on CodeQL or Semgrep; no alteration to Sentinel X, CLI, or Oracle.

---

## 2. Modular Architecture Pipeline

```text
Source Code (.js / .ts)
         │
         ▼
┌───────────────────────────┐
│ 1. AST & CST Normalizer   │ (Babel / Acorn Parser — Bounded AST)
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ 2. Program Graph Builder  │ (Control Flow Graph + Symbol / Scope Table)
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ 3. Semantic Analyzers     │
│  ├─ Prototype Invariants  │ (Recursive merge/assign key-guard dominance)
│  ├─ ReDoS Automata Engine │ (NFA state ambiguity / nested quantifier solver)
│  └─ Taint Flow Evaluator  │ (Source-to-sink interprocedural taint propagation)
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ 4. Proof Witness & SARIF  │ (Causal chain, path trace, confidence score)
└───────────────────────────┘
```

---

## 3. Output Schema Contract

Every analysis output produced by Sentinel Y conforms to the following deterministic JSON contract:

```json
{
  "engine": "sentinel-y",
  "engineVersion": "0.1.0-alpha",
  "analyzedCommitSha": "string",
  "targetFile": "string",
  "ruleId": "Y-PROTO-001 | Y-REDOS-001 | Y-TAINT-001",
  "cwe": "CWE-1321 | CWE-1333 | CWE-77",
  "verdict": "VULNERABILITY_CONFIRMED | INVARIANT_PRESERVED | UNRESOLVED_FLOW",
  "confidence": "HIGH | MEDIUM | LOW",
  "proofWitness": {
    "sourceLocation": { "file": "...", "line": 0 },
    "sinkLocation": { "file": "...", "line": 0 },
    "violatedInvariant": "string",
    "missingGuard": "string",
    "causalPath": [
      { "file": "...", "line": 0, "symbol": "...", "action": "INPUT" },
      { "file": "...", "line": 0, "symbol": "...", "action": "PROPAGATE" },
      { "file": "...", "line": 0, "symbol": "...", "action": "UNSANITIZED_SINK" }
    ]
  },
  "discriminationStatus": "PATCH_CONFIRMED_CLEAN | REVISION_VULNERABLE"
}
```

---

## 4. Shadow-Mode Integration Protocol with Sentinel Cloud

In production Sentinel Cloud:
1. Sentinel X (the existing frozen detector) executes deterministically.
2. Sentinel Y runs asynchronously in shadow mode on repository jobs.
3. An **Arbitration Layer** correlates findings without overriding Sentinel X verdicts until Y completes its independent evaluation campaign.
