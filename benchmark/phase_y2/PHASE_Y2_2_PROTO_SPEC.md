# Sentinel Y v0.2 — Prototype Pollution Invariant & Object Semantics Specification

**Document Version:** 0.2.0  
**Status:** SPECIFICATION & ENGINEERING DESIGN  
**Target Rule:** `Y-PROTO-001`  
**CWE Mapping:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)  
**Supersedes:** `PHASE_Y2_ENGINE_IMPLEMENTATION_SPEC.md` (Section 4)  

---

## 1. Executive Summary & Problem Formulation

In Sentinel Y v0.1.0-alpha, `Y-PROTO-001` evaluated a coarse syntactic invariant: any property-enumerating loop (`for..in`, `Object.keys()`) that contained a dynamic write (`target[key] = val` or `mixin(target, val, key)`) was classified as a `CONFIRMED` prototype pollution unless an explicit key validator (`isValidKey` or `__proto__` + `constructor`) was present.

### Observed Failure Modes in Phase Y3
1. **Benign False Alarms (42.86% FPR on Controls):** In `jsonwebtoken`, `ejs`, and `socket.io`, standard configuration merges (`header[k] = options.header[k]`, `opts[p] = data[p]`, `this.settings[i] = options[i]`) triggered alerts despite operating on shallow, non-pollutable target objects.
2. **Persistent Alarms across Patches:** In `minimist` and `json-pointer`, the analyzer fired on both vulnerable and patched revisions because internal non-vulnerable loops or external helper guards (`isPrototypePollution(key)`) could not be resolved.
3. **Flawed Assumption:** Treating shallow copies as inherently benign is dangerous (a shallow write `target[key] = val` CAN pollute `Object.prototype` if `key === '__proto__'` and `target` inherits from `Object.prototype`). Conversely, treating all dynamic writes as confirmed vulnerabilities causes unmanageable false positives.

Sentinel Y v0.2 replaces the naive syntactic check with a **semantic model of key origin, receiver identity, mutation semantics, and guard effectiveness**.

---

## 2. Invariant Model: The 4-Tuple Condition

A dynamic property write constitutes an exploitable Prototype Pollution vulnerability if and only if all four conditions of the **Mutation 4-Tuple** are satisfied:

$$\text{Vuln}(\text{op}) \iff \mathcal{A}(\text{key}) \land \mathcal{R}(\text{target}) \land \mathcal{M}(\text{op}) \land \neg \mathcal{G}(\text{guard})$$

Where:
1. $\mathcal{A}(\text{key})$ (**Attacker Controllability**): The property key originates from untrusted input, user-supplied arguments, or external unvalidated objects.
2. $\mathcal{R}(\text{target})$ (**Receiver Prototype Vulnerability**): The target object inherits from `Object.prototype` (or is an arbitrary receiver) and is NOT a null-prototype dictionary (`Object.create(null)`), a primitive, or a freshly localized isolated map.
3. $\mathcal{M}(\text{op})$ (**Mutation Operation Semantics**): The assignment performs a prototype-traversing mutation (e.g., indexed assignment `target[key] = val`, recursive property traversal) and is NOT an own-property definition (`Object.defineProperty`) or a frozen/sealed mutation.
4. $\mathcal{G}(\text{guard})$ (**Effective Guard Coverage**): The key has NOT been validated against dangerous prototype keys (`__proto__`, `constructor`, `prototype`).

---

## 3. Detailed Component Semantics

### 3.1 Receiver Identity & Object Semantics $\mathcal{R}(\text{target})$

The analyzer inspects how `target` is instantiated and used:

| Receiver Category | Syntax / Pattern | Prototype Semantics | Vulnerability Posture |
|---|---|---|---|
| **Null Prototype** | `Object.create(null)` | No `__proto__` setter; setting `obj['__proto__']` creates an own property | **IMMUNE** (`CLEAN_WITHIN_SCOPE`) |
| **Object Literal** | `const target = {}` (local) | Inherits `Object.prototype`. Shallow write can set prototype; but if non-exported and immediately consumed, risk is bounded | **CANDIDATE** (requires path context) |
| **Existing Target / Rest Parameter** | `function merge(target, ...rest)` | Modifies caller-supplied object. Can pollute global prototype if caller passes existing instance | **HIGH RISK** (`CONFIRMED` if recursive or unprotected) |
| **Class Instance Settings** | `this.settings[key] = val` | Internal instance dictionary. Often populated from sanitized internal options | **LOW CONFIDENCE** (`CANDIDATE`, not `CONFIRMED`) |
| **Defensive Property Definition** | `Object.defineProperty(target, key, ...)` | Defines own property directly on target; does NOT invoke `Object.prototype` setter | **IMMUNE** (`CLEAN_WITHIN_SCOPE` - the `json5` fix) |

### 3.2 Key Origin & Controllability $\mathcal{A}(\text{key})$

The key's path of arrival determines whether it represents attacker input:

1. **Uncontrolled Key (Internal Constants / Numerical Indices):**
   - Array index iteration: `for (let i = 0; i < arr.length; i++)` -> Key is numeric string (`"0"`, `"1"`). Cannot pollute prototype. -> `CLEAN_WITHIN_SCOPE`.
   - String literals: `target['data'] = val` -> Not dynamic. -> `CLEAN_WITHIN_SCOPE`.
2. **Externally Controlled Key:**
   - Parameter object traversal: `for (let key in userSuppliedObject)` where `userSuppliedObject` is a function argument.
   - Parsed payload traversal: `JSON.parse` / query string / CLI arguments (e.g. `minimist`).
3. **Internal Configuration Merge:**
   - `options.header[k]` where `options` is typed or localized.

### 3.3 Mutation Semantics $\mathcal{M}(\text{op})$: Shallow vs. Recursive

Sentinel Y v0.2 formally distinguishes **two distinct exploit modes**:

#### Mode 1: Shallow Direct Pollution (`__proto__` setter exploit)
```javascript
target[key] = value; // where key === '__proto__' and value is an Object
```
- **Prerequisite:** `value` must be an object containing properties to inject onto `Object.prototype`.
- **Mitigation:** Guard checking `key === '__proto__'` OR `target = Object.create(null)` OR `Object.defineProperty`.
- **Note:** Incomplete guard (`key !== '__proto__'`) DOES prevent Mode 1!

#### Mode 2: Recursive Deep Pollution (`constructor.prototype` chain exploit)
```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]); // resolves target['constructor']['prototype']
    } else {
      target[key] = source[key];
    }
  }
}
```
- **Prerequisite:** Recursive traversal into child objects.
- **Exploit payload:** `{"constructor": {"prototype": {"polluted": true}}}`.
- **Mitigation:** Requires filtering BOTH `__proto__` AND `constructor` (or `prototype`). Guard checking only `__proto__` fails against Mode 2 (the `mixin-deep` CVE-2019-10746 bug).

### 3.4 Guard Effectiveness & Helper Function Summaries $\mathcal{G}(\text{guard})$

The analyzer computes guard strength via two tiers:

#### Tier 1: Inline Guard Analysis
- **Full Guard:**
  - `isValidKey(key)` (with validator checking `__proto__`, `constructor`, `prototype`)
  - `key !== '__proto__' && key !== 'constructor' && key !== 'prototype'`
  - `['__proto__', 'constructor', 'prototype'].includes(key)`
  - `Object.prototype.hasOwnProperty.call(target, key)` combined with own-property write
- **Partial Guard:**
  - `key !== '__proto__'` (protects Mode 1 only; vulnerable to Mode 2 if recursion exists)

#### Tier 2: Inter-Procedural Helper Summary (File Scope)
When a function calls a local helper guard `if (!isSafe(key)) continue;` or `if (isPrototypePollution(key)) continue;`:
- The analyzer summarizes functions matching `is*Proto*`, `is*Safe*Key`, `hasKey`, `isValidKey`.
- If the helper contains key checks, calls to it inside the loop body grant guard status to that loop.

---

## 4. Verdict Classification Taxonomy

Findings are no longer emitted as a binary yes/no. Every analysis output is deterministically classified:

```
                  [Dynamic Property Write Identified]
                                  │
                 Is Target Immune (Object.defineProperty,
                 Object.create(null), Numeric index)?
                                 ╱ ╲
                               YES  NO
                               ╱     ╲
            [CLEAN_WITHIN_SCOPE]      Is Key Controlled by Attacker?
                                               ╱ ╲
                                             NO   YES
                                             ╱     ╲
                           [CLEAN_WITHIN_SCOPE]    Does Full Guard Exist?
                                                           ╱ ╲
                                                         YES  NO
                                                         ╱     ╲
                                      [CLEAN_WITHIN_SCOPE]      Is Merge Recursive?
                                                                        ╱ ╲
                                                                      YES  NO
                                                                      ╱     ╲
                                                            [CONFIRMED]   Is RHS Object &
                                                                          Unchecked __proto__?
                                                                                  ╱ ╲
                                                                                YES  NO
                                                                                ╱     ╲
                                                                      [CONFIRMED]   [CANDIDATE]
```

### Definitions:
- **`CONFIRMED`:** All 4 conditions of the Mutation 4-Tuple are proven: attacker key, pollutable receiver, dangerous mutation (recursive merge or shallow `__proto__` object assignment), missing required guard. High confidence true positive.
- **`CANDIDATE`:** Dynamic indexed write detected on an object, but evidence of external attacker reachability or recursive traversal is ambiguous (e.g., shallow dictionary copy). Requires secondary review.
- **`CLEAN_WITHIN_SCOPE`:** Safe construction proven: null prototype, `Object.defineProperty`, full key validation, or numerical indexing.
- **`UNRESOLVED`:** Complex control flow (e.g., external module delegation, multi-file propagation) prevents static conclusion.

---

## 5. Regression & Verification Test Suite

The engine must pass regression tests on both calibration and diagnostic holdout fixtures:

1. **`deep-extend` (P5-013):** Safe getter replacement (`safeGetProperty`).
   - Vulnerable: `CONFIRMED`
   - Patched: `CLEAN_WITHIN_SCOPE`
2. **`mixin-deep` (P5-015):** Incomplete guard (`if (key !== '__proto__')`) on recursive merge.
   - Vulnerable: `CONFIRMED` (Mode 2 recursive pollution detected)
   - Patched: `CLEAN_WITHIN_SCOPE` (`isValidKey` helper recognized)
3. **`json5` (P5-029):** Structural remediation via `Object.defineProperty`.
   - Vulnerable: `CONFIRMED` (Dynamic assignment sink)
   - Patched: `CLEAN_WITHIN_SCOPE` (`Object.defineProperty` recognized as immune)
4. **`jsonwebtoken` (CTRL-03):** Shallow configuration copy (`header[k] = options.header[k]`).
   - Expected: `CLEAN_WITHIN_SCOPE` or `CANDIDATE` (never `CONFIRMED`)
5. **`ejs` (CTRL-05):** Shallow template options merge (`opts[p] = data[p]`).
   - Expected: `CLEAN_WITHIN_SCOPE` or `CANDIDATE` (never `CONFIRMED`)
6. **`socket.io` (CTRL-07):** Internal settings store (`this.settings[i] = options[i]`).
   - Expected: `CLEAN_WITHIN_SCOPE` or `CANDIDATE` (never `CONFIRMED`)
7. **`json-pointer` (P5-016):** Local helper summary resolution (`isPrototypePollution`).
   - Expected: Distinguishes helper-protected write.
