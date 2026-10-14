# Prospective Benchmark Runner Contract V1

**Version:** 1.0.0  
**Interface:** JSONL Standard Stream Output  
**Execution Environment:** Isolated Sandbox (Read-Only Target Clones)  

---

## 1. Input Specification

The runner receives an input array or manifest of opaque snapshot descriptors:

```json
{
  "opaqueCaseId": "CASE-1042-9XBA",
  "revisionType": "VULNERABLE",
  "cloneLocalPath": "/isolated_clones/repo_xyz",
  "commitSha": "a1b2c3d4e5f67890123456789012345678901234",
  "targetFiles": ["lib/core/parser.js"]
}
```

The runner does **not** receive:
- Package name or repository URL.
- CVE identifier or GHSA identifier.
- Expected rule or ground truth classification.

---

## 2. Output Schema per Revision (Streamed to JSONL)

Every execution must output exactly one JSON object per revision following this strict schema:

```json
{
  "opaqueCaseId": "CASE-1042-9XBA",
  "revisionType": "VULNERABLE",
  "engineVersion": "0.2.0",
  "executionStatus": "COMPLETED",
  "exitCode": 0,
  "durationMs": 412,
  "findingsCountTotal": 1,
  "findingsCountConfirmed": 1,
  "findingsCountCandidate": 0,
  "findings": [
    {
      "findingId": "FND-001",
      "ruleId": "Y-PROTO-001",
      "verdict": "CONFIRMED",
      "confidence": "HIGH",
      "file": "lib/core/parser.js",
      "line": 42,
      "snippet": "target[key] = val",
      "proofWitness": {
        "sourceLocation": { "file": "lib/core/parser.js", "line": 35, "symbol": "key" },
        "sinkLocation": { "file": "lib/core/parser.js", "line": 42, "symbol": "key" },
        "violatedInvariant": "Key assigned dynamically without explicit prototype filter",
        "missingGuard": "No __proto__ or constructor guard detected"
      }
    }
  ]
}
```

---

## 3. Mandatory Execution Status Codes

The runner must strictly emit one of the following execution status codes:

1. `COMPLETED`: AST traversal completed cleanly and all target files evaluated.
2. `TIMEOUT`: Execution exceeded 180 seconds.
3. `HEAP_EXHAUSTION`: Process exceeded memory limits.
4. `PARSE_ERROR`: Target file contains unparseable syntax or unsupported grammar.
5. `FILE_ACCESS_ERROR`: Target file missing at specified commit.

**Strict Prohibition:** The runner is forbidden from substituting an empty findings list `[]` when `executionStatus !== 'COMPLETED'`.
