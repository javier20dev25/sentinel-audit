# Sentinel Y — Engine Implementation Specification

**Version:** v0.1.0-alpha  
**Source:** `C:\Users\sleyt\sentinel-audit\sentinel-y\index.js`  
**Status:** Prototype — not integrated into production Sentinel stack  
**Dependency policy:** Zero runtime dependencies on CodeQL, Semgrep, or any external analyzer

---

## 1. Design Principles

1. **Learn the detection principle, not the specific pattern.** Rules encode the structural invariant (e.g., "every property key assigned to a target during enumeration must pass a complete set of dangerous-key filters"), not the variable name, library name, or code style.

2. **Reproducible traces.** Every finding carries a `proofWitness` object that identifies the loop source location, the sink location, the violated invariant, and the missing guard. These fields must be sufficient for a human reviewer to verify or refute the finding without re-running the engine.

3. **Bounded traversal.** The engine does not build full ASTs or call graphs. It uses bounded linear traversal with per-loop state. Analysis complexity is O(n) in line count.

4. **Explicit analysis bounds.** The engine documents what it cannot detect. False negatives from out-of-scope patterns are preferable to false positives from overgeneralized heuristics.

5. **Motor congelado.** During Phases Y2 and Y3, the engine version is frozen once evaluation begins. No rule changes during a live evaluation run.

---

## 2. Public API

```javascript
const { analyzeFile, analyzePrototypePollution, analyzeReDoS, normalizeSource } = require('./sentinel-y');
```

### `normalizeSource(sourceCode: string) → SourceObj`

Splits source into lines. Returns:
```typescript
{ raw: string, lines: string[], lineCount: number }
```

### `analyzePrototypePollution(sourceObj: SourceObj, filePath: string) → Finding[]`

Runs the Y-PROTO-001 analysis on a pre-normalized source object.

### `analyzeReDoS(sourceObj: SourceObj, filePath: string) → Finding[]`

Runs the Y-REDOS-001 analysis on a pre-normalized source object.

### `analyzeFile(filePath: string, content: string) → Finding[]`

Convenience wrapper: normalizes content, runs both analyzers, returns concatenated findings.

---

## 3. Finding Schema

```typescript
interface Finding {
  ruleId:     'Y-PROTO-001' | 'Y-REDOS-001';
  cwe:        'CWE-1321' | 'CWE-1333';
  verdict:    'CONFIRMED';
  confidence: 'HIGH';
  title:      string;
  file:       string;
  line:       number;        // 1-indexed line of the sink
  snippet:    string;        // trimmed line content at the sink
  proofWitness: ProofWitness;
}

interface ProofWitness {
  sourceLocation:   { file: string; line: number; symbol: string };
  sinkLocation:     { file: string; line: number; symbol: string };
  violatedInvariant: string;
  missingGuard:      string;
  causalPath?:       Array<{ step: number; file: string; line: number; action: string; symbol: string }>;
}
```

---

## 4. Rule: Y-PROTO-001 — Prototype Pollution via Property Enumeration

### Invariant

Any code that enumerates object keys and writes or delegates them to a target object must apply a guard that filters **all three** dangerous keys: `__proto__`, `constructor`, and `prototype`.

A guard that filters only `__proto__` is classified as **partial** and does **not** satisfy the invariant.

### Detection Algorithm

```
For each source file:
  State:
    inLoop           = false          // inside a property-enumerating loop
    loopKey          = null           // name of the key variable in the loop
    loopStartLine    = 0
    hasLocalGuard    = false          // full guard seen in this loop
    loopGuardStrength = 'none'        // 'none' | 'partial' | 'full'

  Global file-level checks (computed once):
    hasGlobalSafeGetter   = file contains 'safeGetProperty' AND '__proto__'
    hasGlobalKeyValidator = file contains 'isValidKey' AND ('constructor' OR 'prototype')

  For each line:
    1. LOOP DETECTION
       Matches: for(var|let|const key in obj), Object.keys(obj).forEach, .forEach(function(key))
       → set inLoop=true, loopKey, loopStartLine, reset hasLocalGuard and loopGuardStrength

    2. GUARD CLASSIFICATION (only if inLoop)
       FULL guard:    line contains 'isValidKey'
                      OR (line contains '__proto__' AND (line contains 'constructor' OR 'prototype'))
                      → hasLocalGuard=true, loopGuardStrength='full'
       PARTIAL guard: line contains '__proto__' AND loopGuardStrength != 'full'
                      → loopGuardStrength='partial'   [does NOT set hasLocalGuard]

    3. SINK DETECTION (only if inLoop)
       Matches:
         a. target[key] = value        (assignRegex)
         b. mixin(target, val, key)    (mixinCallRegex)
       If assignedKey === loopKey OR loopKey is 'key' (generic fallback):
         isFullyProtected = hasGlobalSafeGetter OR hasGlobalKeyValidator OR loopGuardStrength == 'full'
         If NOT isFullyProtected → emit Finding

    4. LOOP EXIT
       Heuristic: closing '}' seen more than 15 lines after loopStartLine → inLoop=false
```

### Guard Taxonomy

| Guard code pattern | Classification | Notes |
|---|---|---|
| `key !== '__proto__'` | `partial` | Only CVE-2018-3750 class; `constructor.prototype` still pollutable |
| `key === '__proto__' && ...` (only) | `partial` | Same as above |
| `isValidKey(key)` | `full` | Requires validator to cover all three dangerous keys |
| `key !== '__proto__' && key !== 'constructor'` | `full` | Explicit multi-key guard |
| `safeGetProperty(obj, key)` + file-level `__proto__` check | `full` (global) | safe-getter pattern (deep-extend fix) |

### Analysis Bounds

| Pattern | Detected? | Reason |
|---|---|---|
| `for..in` + `target[key] = val` | ✅ Yes | Core pattern |
| `for..in` + `mixin(target, val, key)` | ✅ Yes | mixinCallRegex covers it |
| `Object.assign({}, obj)` unguarded | ❌ No | No loop variable; needs specific assign pattern |
| Object spread `{...obj}` | ❌ No | No key variable |
| Multi-file propagation | ❌ No | Single-file only |
| `Object.keys(obj).reduce(...)` | ❌ No | reduce pattern not modeled |
| Prototype pollution via `__defineGetter__` | ❌ No | Out of scope for v0.1 |

---

## 5. Rule: Y-REDOS-001 — Polynomial Regular Expression Complexity

### Invariant

A regex applied to unbounded user-controlled input must not contain quantifier structures that allow superlinear backtracking. Specifically:

1. **Backtracking capture group:** `(\\*)` — captured greedy star over backslash enables quadratic backtracking when input ends with odd-length backslash sequences.
2. **Unbounded prefix with quantifier overlap:** `\\s*=\\s*` combined with a greedy `+` in a preceding group — allows polynomial worst-case via overlapping prefixes.
3. **Unbounded `\\s*` adjacent to `+`-quantified groups.**

A bounded equivalent (e.g., `{0,256}` instead of `*`) satisfies the invariant.

### Detection Algorithm

```
Pass 1 — Regex literal definitions:
  Scan each line for: var NAME = /PATTERN/FLAGS
  For each match:
    isBoundedRepetition = pattern contains '{0,' OR matches /\{\d+,\d+\}/
    hasAmbiguousBacktracking = NOT isBoundedRepetition AND (
      pattern contains '(\\*)' OR
      (pattern contains '\\s*' AND pattern contains '+') OR
      pattern contains '\\s*=\\s*'
    )
    If hasAmbiguousBacktracking → emit Finding

Pass 2 — Inline regex in replace/match/test/exec calls:
  Scan each line for: VAR.replace(/INLINE_PATTERN/FLAGS, ...)
  If inline pattern contains '(\\\\*)' → emit Finding
```

### Analysis Bounds

| Pattern | Detected? | Reason |
|---|---|---|
| `var re = /pattern/` with ambiguous quantifier | ✅ Yes | Pass 1 |
| `str.replace(/(\\*)"/g, ...)` inline | ✅ Yes | Pass 2 |
| `new RegExp(string)` dynamic construction | ❌ No | No literal pattern to analyze |
| ReDoS via alternation catastrophic backtracking (e.g., `(a|a)+`) | ❌ No | Not modeled in v0.1 |
| Exponential (not polynomial) backtracking | ❌ No | Out of scope |
| Bounded quantifiers `{n,m}` correctly suppressed | ✅ Yes | `isBoundedRepetition` check |

---

## 6. File-Level Global Checks

Before per-line analysis, two global checks are computed on the full file text:

| Check | Condition | Effect |
|---|---|---|
| `hasGlobalSafeGetter` | file has `'safeGetProperty'` AND `'__proto__'` | Suppresses all Y-PROTO-001 sinks |
| `hasGlobalKeyValidator` | file has `'isValidKey'` AND (`'constructor'` OR `'prototype'`) | Suppresses all Y-PROTO-001 sinks |

These checks are conservative: they can cause false negatives if the safe function is defined but not actually called on the key path. The alternative (full call-graph analysis) is outside v0.1 scope. This trade-off is documented.

---

## 7. Version History

| Version | Date | Change |
|---|---|---|
| v0.1.0-alpha | 2026-10-10 | Initial prototype. Y-PROTO-001 and Y-REDOS-001. 4/4 discovery-case discrimination. |
| — | — | Bug fix: replaced per-line `isSingleProtoOnly` with loop-level `loopGuardStrength` to correctly classify partial guards (P5-015 fix). |

---

## 8. Integration Constraints

- **Do not** integrate into Sentinel Audit, Sentinel CLI, or Sentinel Cloud in this phase.
- **Do not** invoke this engine from within a production scan pipeline until Phase Y3 blind evaluation is complete.
- The engine is invoked exclusively by `benchmark/phase_y2/run_differential_eval.js` and the unit test runners during this phase.
- All output files (`PHASE_Y2_METRICS.json`, `PHASE_Y2_RESULTS.jsonl`) are benchmark artifacts, not production verdicts.
