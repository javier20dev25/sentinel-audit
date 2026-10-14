# Phase Y2 CodeQL Query Mechanism Review

## 1. Verified Query Identities & Pack Versions

- **CodeQL Distribution:** 2.27.1 (`sha: 938af3639d07`)
- **Query Pack:** `codeql/javascript-queries@2.4.6`
- **Query File Paths Inspected:**
  1. `Security/CWE-915/PrototypePollutingFunction.ql` (ID: `js/prototype-pollution-utility`)
  2. `Security/CWE-915/PrototypePollutingAssignment.ql` (ID: `js/prototype-polluting-assignment`)
  3. `Performance/PolynomialReDoS.ql` (ID: `js/polynomial-redos`)

---

## 2. Reconstructed Analytical Models

### A. `js/prototype-pollution-utility`
- **Model Type:** Interprocedural path query tracking property enumeration $\to$ property write.
- **Source:** Enumerated property names from loops (`for..in`, `Object.keys()`, `x.split(".")`).
- **Sink:** Dynamic property access `target[key] = ...`.
- **Sanitizers:** Checks if a condition guards the assignment by ensuring the key is not `__proto__`, `constructor`, or `prototype`.
- **Finding:** A function that recursively merges or copies properties without this dominant guard is classified as a prototype-polluting utility.

### B. `js/polynomial-redos`
- **Model Type:** Automata ambiguity analysis + path flow from uncontrolled data.
- **Automata Model:** Computes whether the regular expression contains pumpable ambiguity states where multiple paths in the NFA accept repeated subpatterns.
- **Flow Model:** Verifies if the string argument to `.match()`, `.test()`, `.replace()`, or `.exec()` is derived from an external or exported function parameter.
- **Three-Tier Classification for Sentinel Y:**
  1. **Structural Pattern Candidate:** The regex AST exhibits ambiguous repetition (e.g. `(a+)+` or `\s*=\s*` with overlapping delimiters).
  2. **Reachable Candidate:** String input originates from library exports or external inputs without length guards.
  3. **Confirmed Vulnerability:** Both structural ambiguity and unconstrained input reachability are proven.
