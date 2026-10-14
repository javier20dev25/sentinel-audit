# Phase Y2.2 — Technical Claim & Architectural Boundary Audit

**Audit Date:** 2026-10-10  
**Status:** FORENSIC AUDIT COMPLETE  
**Engine Inspected:** Sentinel Y v0.2.0 (`sentinel-y/v0.2/index.js` — FROZEN)  
**Evidence Artifact:** `PHASE_Y2_2_COUNTEREXAMPLES.jsonl`  

---

## 1. Executive Summary

A thorough code-level inspection was performed on `sentinel-y/v0.2/index.js` without altering a single line of code. The objective was to audit the actual behavior of Sentinel Y v0.2 against the theoretical invariants stated in `PHASE_Y2_2_PROTO_SPEC.md` and `PHASE_Y2_2_REDOS_SPEC.md`.

### Core Verdict on Gates G5 and G6:
- **Gate G5 (Prototype Pollution Semantics):** **PARTIALLY_VERIFIED**. While distinguishing shallow config copies (`header[k] = options.header[k]`) successfully reduced benign control false alarms, the engine relies on keyword heuristics that fail on class prototype method assignments (`CE-02`) and nested property paths (`CE-03`).
- **Gate G6 (ReDoS AST Structural Analysis):** **PARTIALLY_VERIFIED**. The engine broadened pattern detection beyond literal calibration strings, but suffers from **critical global over-suppression bugs** (`CE-04` and `CE-05`) where finite bounds or lookaheads anywhere in a regex string blindly suppress catastrophic backtracking in other subpatterns.

---

## 2. Comprehensive Forensic Audit of Counterexamples (CE-01 to CE-05)

All five counterexamples were executed directly against the frozen `sentinel-y/v0.2/index.js` engine:

```
┌────────┬─────────────────────────┬───────────────────┬────────────────────┬────────────────────────┐
│ ID     │ Vulnerability Family    │ Snippet Evaluated │ v0.2 Engine Output │ Theoretical Reality    │
├────────┼─────────────────────────┼───────────────────┼────────────────────┼────────────────────────┤
│ CE-01  │ Prototype Pollution     │ target[key] = null│ CONFIRMED (1 alert)│ Prototype re-assignment│
│ CE-02  │ Prototype Pollution     │ Service.proto[m]=f│ CLEAN (0 alerts)   │ Class prototype inject │
│ CE-03  │ Prototype Pollution     │ obj[p] = true     │ CONFIRMED (1 alert)│ Deep boolean injection │
│ CE-04  │ ReDoS Complexity        │ /(a{0,256})*/     │ CLEAN (0 alerts)   │ Outer unconstrained *  │
│ CE-05  │ ReDoS Complexity        │ /(?=a+)(a+)+/     │ CLEAN (0 alerts)   │ Unprotected (a+)+ group│
└────────┴─────────────────────────┴───────────────────┴────────────────────┴────────────────────────┘
```

### Detailed Evaluation per Case:

#### Counterexample CE-01: Direct `__proto__` Reassignment with `null`
- **Minimal Reproduction Code:**
  ```javascript
  function reassignProto(target, key) { for (let key in obj) { target[key] = null; } }
  ```
- **Engine Output in v0.2:** Emits **1 finding as `CONFIRMED`** prototype pollution.
- **Analysis & Gap:** The v0.2 primitive value filter checks `trimmedVal === 'null'`, but because `target[key] = null` matches `assignRegex` on objects, the engine emits `CONFIRMED`. While assigning `null` to `__proto__` does modify the object prototype (setting `Object.getPrototypeOf(target) === null`), this is a prototype re-assignment / severance operation, distinct from injecting malicious inherited properties onto `Object.prototype`. The engine flags the line, but conflates prototype re-assignment with property pollution.

#### Counterexample CE-02: Dynamic Class Prototype Method Injection
- **Minimal Reproduction Code:**
  ```javascript
  for (let m in userMethods) { Service.prototype[m] = function() { return userMethods[m]; }; }
  ```
- **Engine Output in v0.2:** Emits **0 findings (`CLEAN_WITHIN_SCOPE`)**.
- **Analysis & Gap:** **DEFECT / UNDER-DETECTION**. In `sentinel-y/v0.2/index.js` lines 115-118, `isClassMethodInit` checks:
  ```javascript
  const isClassMethodInit = targetExpr.endsWith('.prototype') && (assignedVal.includes('function') || assignedVal.includes('=>'));
  if (isTargetImmune || isClassMethodInit) continue;
  ```
  The engine unconditionally assumes that assigning a function to `.prototype` is safe class initialization. If the method name `m` is an untrusted user-controlled string, an attacker can overwrite existing core methods (e.g. `authenticate`, `toString`, `valueOf`) on all instances of `Service`.

#### Counterexample CE-03: Nested Property Path Setter with Primitive Boolean Leaf
- **Minimal Reproduction Code:**
  ```javascript
  for (let p in path) { obj[p] = true; }
  ```
- **Engine Output in v0.2:** Emits **1 finding as `CONFIRMED`**.
- **Analysis & Gap:** Although assigning `true` to a shallow flat object literal cannot pollute prototype properties, path setters that dynamically traverse `['constructor', 'prototype', 'isAdmin']` can inject `isAdmin = true` onto `Object.prototype`. The engine flags this construct, but cannot resolve whether `obj` is an isolated flat dictionary or part of an unvalidated property path.

#### Counterexample CE-04: Finite Repetition Nested under Outer Unconstrained Star
- **Minimal Reproduction Code:**
  ```javascript
  var r = /(a{0,256})*/;
  ```
- **Engine Output in v0.2:** Emits **0 findings (`CLEAN_WITHIN_SCOPE`)**.
- **Analysis & Gap:** **DEFECT / OVER-SUPPRESSION**. In `sentinel-y/v0.2/index.js` line 188:
  ```javascript
  const hasBoundedRep = /\{\d+,\d+\}/.test(pattern) || pattern.includes('{0,');
  ...
  isSuperlinearRisk: !hasBoundedRep && !hasLookaheadMitigation && ...
  ```
  Because `{0,` appears in the pattern, `hasBoundedRep` evaluates to `true`, forcing `isSuperlinearRisk` to `false`. However, the outer `*` quantifier can still backtrack superlinearly over combinations of inner 256-character sequences on long non-matching inputs. The presence of `{0,` anywhere in the regex string suppresses the entire analysis.

#### Counterexample CE-05: Lookahead Assertion without Group Following Isolation
- **Minimal Reproduction Code:**
  ```javascript
  var r = /(?=a+)(a+)+/;
  ```
- **Engine Output in v0.2:** Emits **0 findings (`CLEAN_WITHIN_SCOPE`)**.
- **Analysis & Gap:** **DEFECT / OVER-SUPPRESSION**. In `sentinel-y/v0.2/index.js` line 204:
  ```javascript
  const hasLookaheadMitigation = pattern.includes('(?=') || pattern.includes('(?!');
  ```
  The engine treats the presence of `(?=` anywhere in the string as a global mitigation. In `/(?=a+)(a+)+/`, the lookahead `(?=a+)` does not consume characters or isolate the subsequent group `(a+)+`, which exhibits catastrophic exponential backtracking.

---

## 3. Version Immutability & Future Specification (v0.3 Roadmap)

In accordance with strict benchmark governance:
1. `sentinel-y/v0.2/index.js` remains **strictly frozen and unmodified**.
2. The defects identified in `CE-02`, `CE-04`, and `CE-05` must be addressed in an independent future version (**Sentinel Y v0.3**) prior to prospective benchmark execution.
3. Sentinel Y v0.3 will require:
   - Scoped quantifier bounds evaluation (evaluating `{0,m}` only for the targeted sub-AST node).
   - Enclosed lookahead verification (ensuring atomic lookaheads wrap the actual repeated term).
   - Origin taint checks for class prototype property assignments.
