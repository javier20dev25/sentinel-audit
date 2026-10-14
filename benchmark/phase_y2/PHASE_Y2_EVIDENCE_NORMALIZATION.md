# Phase Y2 Evidence Normalization & Audit Reconciliation

## 1. Executive Summary

This document normalizes metadata, reconciles CVE discrepancies against official GitHub Security Advisories (GHSA), audits fixing diffs, and establishes empirical baselines for the Phase Y2 prototype development.

---

## 2. Verification and Correction of CVE Identifiers

| Case ID | Package Name | Advisory ID | Manifest CVE | Corrected CVE | Advisory Title & Reference | Original CWE | Adjudicated Weakness Class |
|:---|:---|:---|:---:|:---:|:---|:---:|:---|
| **P5-013** | `deep-extend` | `GHSA-hr2v-3952-633q` | CVE-2018-3750 | **CVE-2018-3750** | Prototype Pollution in deep-extend | CWE-20 | **CWE-1321 (Prototype Pollution)** |
| **P5-015** | `mixin-deep` | `GHSA-fhjf-83wg-r2j9` | CVE-2019-10746 | **CVE-2019-10746** | Prototype Pollution in mixin-deep (corrected from 2018-3777) | CWE-88 | **CWE-1321 (Prototype Pollution)** |
| **P5-033** | `tough-cookie` | `GHSA-g7q5-pjjr-gqvp` | CVE-2017-15010 | **CVE-2017-15010** | ReDoS in tough-cookie (corrected from 2023-26136) | CWE-400 | **CWE-1333 (ReDoS / Resource Exhaustion)** |
| **P5-041** | `cross-spawn` | `GHSA-3xgq-45jj-v275` | CVE-2024-21538 | **CVE-2024-21538** | ReDoS in cross-spawn (corrected from 2024-21508) | CWE-1333 | **CWE-1333 (ReDoS / Polynomial Backtracking)** |

> **Audit Note on CWE Mapping:** The original manifests carried upstream advisory labels (e.g. CWE-20, CWE-88, CWE-400). In our evaluation and engine specifications, the original CWE is preserved verbatim in `manifestCwe`, while `adjudicatedWeakness` explicitly classifies the defect's structural property.

---

## 3. Audit of the 4 Reference Discovery Diffs

### 1. `P5-013` (`deep-extend`)
- **Vulnerable SHA:** `9653940a` $\to$ **Fix SHA:** `9423fae8`
- **File:** `lib/deep-extend.js`
- **Code Change:**
  ```javascript
  // Fix adds:
  if (key === '__proto__') {
    continue;
  }
  ```
- **Semantic Finding:** The recursive merge function previously copied properties into `target[key]` without sanitizing `__proto__`. The fix introduces an explicit continue guard dominating the assignment.

### 2. `P5-015` (`mixin-deep`)
- **Vulnerable SHA:** `9925af76` $\to$ **Fix SHA:** `8f464c8c`
- **File:** `index.js`
- **Code Change:** Introduces `isValidKey(key)` checking for `__proto__`, `constructor`, and `prototype` in the recursive assignment loop.

### 3. `P5-033` (`tough-cookie`)
- **Vulnerable SHA:** `fcc8abfa` $\to$ **Fix SHA:** `f1ed420a`
- **File:** `lib/cookie.js`
- **Code Change:**
  ```javascript
  - var COOKIE_PAIR = /^(([^=;]+))\s*=\s*([^\n\r\0]*)/;
  + var COOKIE_PAIR = /^(([^=;]+))\s{0,256}=\s*([^\n\r\0]*)/;
  ```
- **Semantic Finding:** Unbounded whitespace repetition `\s*` paired with leading captures allowed catastrophic backtracking. The fix caps the repetition to bounded `{0,256}`.

### 4. `P5-041` (`cross-spawn`)
- **Vulnerable SHA:** `9521e2da` $\to$ **Fix SHA:** `5ff3a07d`
- **File:** `lib/util/escape.js`
- **Code Change:**
  ```javascript
  - arg = arg.replace(/(\\*)"/g, '$1$1\\"');
  + arg = arg.replace(/(?=\\*?)"/g, '$1$1\\"');
  ```
- **Semantic Finding:** Replaced ambiguous nested backslash regex with non-backtracking lookaheads to disable catastrophic backtracking.

---

## 4. Audit of Persistent and Unrelated Reference Findings

1. **`P5-014` (`set-value`)**: In the vulnerable revision, CodeQL flagged 4 findings. In the patched revision (`95e9d992`), the author filtered keys using `.filter(isValidKey)`. CodeQL still flagged 3 paths (`js/prototype-polluting-assignment`) because CodeQL's taint model did not recognize that array `.filter()` acts as a global sanitizer over all subsequent split segments.
2. **`P5-016` (`json-pointer`)**: CodeQL reported prototype-polluting assignments on both revisions because property writes via pointer path strings are tracked as potential sinks unless explicitly validated at each indirection.
3. **`P5-031` (`semver`)**: The patch for CVE-2015-8855 modified regexes, but older build regexes still contained nested space patterns. CodeQL accurately reported that other regexes in `semver.js` remained superlinear.
4. **`P5-011` (`minimist`)** & **`P5-042` (`body-parser`)**: Confirmed as `UNRELATED_SECURITY_ALERT`.
