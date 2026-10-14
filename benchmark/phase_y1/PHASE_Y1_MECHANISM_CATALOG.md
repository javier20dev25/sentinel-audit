# Phase Y1 Mechanism Catalog: Grounded in Reference Detections

## 1. Executive Summary

This catalog updates our analytical specifications based on **actual execution evidence** from CodeQL (`2.27.1`) with suite `javascript-security-extended.qls` and Semgrep OSS (`1.175.0`) with `p/javascript` over the 26 Phase 5 missed cases (52 snapshots).

### Key Empirical Findings
1. **Semgrep (`p/javascript`) Coverage**: 0 findings in scope across all 26 cases. Generic AST pattern matching without deep dataflow models completely missed logic bugs and library vulnerabilities.
2. **CodeQL (`security-extended`)**: Generated in-scope alerts in **9 / 26** cases, achieving **4 clean paired discriminations** (alert on vulnerable $\to$ clean on patched):
   - **Prototype Pollution**: `P5-013` (`deep-extend`), `P5-015` (`mixin-deep`) via `js/prototype-pollution-utility`.
   - **ReDoS**: `P5-033` (`tough-cookie`), `P5-041` (`cross-spawn`) via `js/polynomial-redos`.
3. **No Reference Detection (17 / 26 = 65.4%)**: Complex framework vulnerabilities (e.g. `sequelize` SQLi AST transformations, `moment` timezone path traversal, `xmldom` recursive parsing) were not detected by standard static suites without specialized domain models.

---

## 2. Reconstructed Mechanism 1: Object & Prototype Mutation Invariants

### Analyzed Case Studies
- **`P5-013` (`deep-extend`, CVE-2018-3750, CWE-20/CWE-1321)**:
  - **CodeQL Query**: `js/prototype-pollution-utility`
  - **Observed CodeFlow**: 9-step path from `lib/deep-extend.js:104` (enumeration key) into recursive copy `target[key] = copy` at L117 without checking if `key === '__proto__'`.
  - **Patch Diff**: Introduces strict filter:
    ```javascript
    if (key === '__proto__') {
      continue;
    }
    ```
  - **Resolution in Patched Revision**: CodeQL recognizes the dominance of the key guard over the property assignment step, clearing the alert completely.

### Mathematical Invariant for Sentinel Y (`Y-PROTO`)
Let $\mathcal{L}$ be an object property copy operation assigning $\text{Target}[\text{Key}] \leftarrow \text{Source}[\text{Key}]$.
A vulnerability exists if and only if:
1. $\text{Key}$ is dynamically supplied (attacker-reachable or external argument).
2. The control-flow path reaching $\mathcal{L}$ does **NOT** contain a sanitizing guard predicate $\mathcal{G}(\text{Key})$ such that:
   $$\mathcal{G}(\text{Key}) \implies \text{Key} \notin \{\text{"__proto__"}, \text{"constructor"}, \text{"prototype"}\}$$
3. $\text{Target}$ is an Object whose prototype chain links to `Object.prototype`.

---

## 3. Reconstructed Mechanism 2: Polynomial Regular Expression Complexity (ReDoS)

### Analyzed Case Studies
- **`P5-033` (`tough-cookie`, CVE-2023-26136, CWE-400/CWE-1333)**:
  - **CodeQL Query**: `js/polynomial-redos`
  - **Observed CodeFlow**: 6-step path from `lib/cookie.js:321` (`str` argument) through `str.trim()` into `COOKIE_OCTETS` regex matching.
  - **Vulnerable Pattern**: Regex contained ambiguous repetitions allowing catastrophic backtracking on sequences starting with `:` and trailing spaces.
  - **Patch Diff**: Replaced the ambiguous regex with bounded character index scans and simplified non-backtracking patterns.
  - **Resolution in Patched Revision**: CodeQL verifies that the simplified regex has linear time complexity $O(n)$, clearing the alert.

### Mathematical Invariant for Sentinel Y (`Y-REDOS`)
Let $\mathcal{R}$ be a regular expression matched against input string $S$ originating from an untrusted source.
A vulnerability exists if:
1. The NFA/DFA state graph of $\mathcal{R}$ contains product states $(q_i, q_j)$ reachable by the same character transition that can pump arbitrary repetitions (ambiguous paths).
2. The input string length $|S|$ is unbounded.
3. Sentinel Y verifies polynomial or exponential complexity $O(|S|^k)$ ($k \ge 2$) using automata cycle analysis.

---

## 4. Synthesis for Sentinel Y Engine Design

Based on empirical reference ground truth, Sentinel Y will prioritize implementing two deterministic, evidence-backed analyzers:
1. **`Y-PROTO-001` (Prototype Mutation Analyzer)**: AST traversal loop + key-guard dominance checker.
2. **`Y-REDOS-001` (Regex Automata Complexity Analyzer)**: Regex AST parser + NFA ambiguity/cycle solver.

Both analyzers will operate purely in JavaScript/TypeScript static analysis without target code execution.
