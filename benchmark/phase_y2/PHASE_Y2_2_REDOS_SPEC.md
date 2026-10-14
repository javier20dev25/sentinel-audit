# Sentinel Y v0.2 — Bounded Regular Expression Complexity (ReDoS) Specification

**Document Version:** 0.2.0  
**Status:** SPECIFICATION & ALGORITHM DESIGN  
**Target Rule:** `Y-REDOS-001`  
**CWE Mapping:** CWE-1333 (Inefficient Regular Expression Complexity)  
**Supersedes:** `PHASE_Y2_ENGINE_IMPLEMENTATION_SPEC.md` (Section 5)  

---

## 1. Executive Summary & Deficit Analysis

In Sentinel Y v0.1.0-alpha, `Y-REDOS-001` relied on literal substring matching for two specific syntactic fragments:
1. `(\\*)` (backtracking captured backslash in `cross-spawn`)
2. `\\s*=\\s*` combined with `+` (cookie delimiter parsing in `tough-cookie`)

### Observed Failure Modes in Phase Y3
- **Total Generalization Breakdown (0/6 on Blind ReDoS Cases):** In `moment` (date regex), `ansi-regex` (terminal escape sequences), `braces` (brace expansion), `semver` (numeric grammar), and `debug` (wildcard parsing), the rule produced **0 findings** across both vulnerable and patched snapshots.
- **Root Cause:** ReDoS vulnerabilities stem from **non-deterministic branching ambiguity in NFA/DFA transitions**, which manifests in diverse grammar structures that cannot be enumerated via fixed token patterns.
- **Architectural Shift:** Sentinel Y v0.2 replaces token memorization with an **explicit regex AST parser and bounded structural ambiguity solver**.

---

## 2. Supported Syntax, Unsupported Constructs & Analysis Bounds

### 2.1 Supported Regex Syntax
Sentinel Y v0.2 parses and analyzes:
- Quantifiers: Greedy (`*`, `+`, `{n,}`), Lazy (`*?`, `+?`), and Bounded (`{n,m}`).
- Disjunctions / Alternations: `(a|b|c)`.
- Character Classes: Simple `[a-z]`, negated `[^a-z]`, shorthand classes (`\s`, `\d`, `\w`, `\S`, `\D`, `\W`).
- Grouping: Capturing `(...)`, Non-capturing `(?:...)`, and Lookaround assertions (`(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`).
- Anchors: `^`, `$`, `\b`, `\B`.

### 2.2 Unsupported Constructs & Conservative Bounds
- **Backreferences (`\1`, `\2`):** Backreferences turn regular expressions into NP-complete matching problems. If a backreference is detected inside a repeated group, the analyzer emits `CANDIDATE_UNRESOLVED_COMPLEXITY` rather than claiming a formal degree bound.
- **Dynamic String Concatenation (`new RegExp(a + b)`):** Dynamic patterns whose sub-expressions cannot be resolved statically at parse time are marked `UNRESOLVED_DYNAMIC_PATTERN`.
- **Claim Limitation Policy:** The analyzer **never claims exact polynomial degree $O(n^k)$ or exponential complexity $O(2^n)$** unless an unambiguous pumping path is formally proven through overlapping transition sets. Otherwise, findings are labeled `STRUCTURAL_AMBIGUITY_CANDIDATE`.

---

## 3. Structural Ambiguity Detection Algorithm

The ReDoS detection pipeline operates in three discrete phases:

### Phase 1: AST Construction
The raw regex literal or static `RegExp` string is converted into a structured AST:
```typescript
type RegexNode =
  | { type: 'Character'; value: string }
  | { type: 'CharacterClass'; negated: boolean; members: string[] }
  | { type: 'Alternation'; branches: RegexNode[] }
  | { type: 'Concatenation'; elements: RegexNode[] }
  | { type: 'Quantifier'; min: number; max: number | Infinity; greedy: boolean; body: RegexNode }
  | { type: 'Group'; capturing: boolean; body: RegexNode }
  | { type: 'Lookaround'; kind: 'ahead-pos' | 'ahead-neg' | 'behind-pos' | 'behind-neg'; body: RegexNode };
```

### Phase 2: Structural Ambiguity Analysis
The analyzer evaluates the AST against three core vulnerability patterns:

#### Pattern A: Nested Repetitive Quantifiers (Star-Height > 1 Ambiguity)
- **Structure:** `(R+)*`, `(R*)+`, `(R+)+`, `(A|B)+` where $\text{overlap}(A, B) \neq \emptyset$.
- **Detection Algorithm:**
  1. For each `Quantifier` node $Q_1$ with $Q_1.\text{max} = \infty$:
  2. Inspect $Q_1.\text{body}$. If it contains an inner `Quantifier` node $Q_2$ with $Q_2.\text{max} = \infty$:
  3. Compute whether $\text{Nullable}(Q_2)$ or $\text{First}(Q_2) \cap \text{Follow}(Q_2) \neq \emptyset$.
  4. If the inner body can match a non-empty string and repeat, the number of match combinations grows superlinearly with input length $n$.

#### Pattern B: Overlapping Alternation under Star/Plus Repetition
- **Structure:** `(e_1 | e_2 | ... | e_k)+`
- **Detection Algorithm:**
  1. Compute First Character Sets: $S_i = \text{FirstSet}(e_i)$.
  2. Check pairwise intersection: $\exists i \neq j \text{ such that } S_i \cap S_j \neq \emptyset$.
  3. If intersecting branches exist and both can consume input under an outer unbounded quantifier, backtracking between $e_i$ and $e_j$ creates exponential/polynomial state explosion upon matching failure.

#### Pattern C: Adjacent Overlapping Quantifiers
- **Structure:** $A^* B^*$ or $A^+ B^*$ where $\text{FirstSet}(A) \cap \text{FirstSet}(B) \neq \emptyset$ and no anchor/boundary separates them.
- **Example:** `([a-z]+)[a-z]*` or `\s*=\s*` with overlapping prefix in `tough-cookie`.

### Phase 3: Mitigation & Reachability Verification
A structural ambiguity finding is downgraded or suppressed if:
1. **Length Bounding:** The pattern is bounded via `{0, m}` where $m \le 256$ (e.g. `tough-cookie` patch: `\s{0,256}`).
2. **Lookahead / Atomic Grouping:** The match uses lookahead assertions to prevent backtracking into prior captures (e.g. `cross-spawn` patch: `(?=\\*?)"`).
3. **Input Length Pre-condition:** Input string is checked for length before regex execution: `if (str.length > 500) return;`.

---

## 4. Multi-Family Grammar Coverage

Sentinel Y v0.2 is designed and calibrated against six distinct grammar families:

| Grammar Family | Exemplar Vulnerability | Vulnerable AST Feature | Patched Remediation |
|---|---|---|---|
| **Escape Sequences** | `cross-spawn` (CVE-2024-21538) | Backtracking captured backslashes `(\\*)` | Atomic lookahead assertion `(?=\\*?)"` |
| **Delimited Pairs** | `tough-cookie` (CVE-2017-15010) | Unbounded whitespace `\s*=\s*` with overlapping capture | Length-bounded quantifier `\s{0,256}` |
| **Numeric Versions** | `semver` (CVE-2015-8855) | Repeated optional pre-release / build metadata `(?:-[0-9A-Za-z.-]+)?` | Disjoint character sets & explicit hyphen boundaries |
| **ANSI Terminal Codes**| `ansi-regex` (CVE-2021-3807) | Overlapping bracket wildcards `(?:\x1b\[[0-9;]*[a-zA-Z])` | Factored prefixes & atomic terminal branches |
| **Date / Time Formats**| `moment` (CVE-2017-18214) | Overlapping date part tokens with trailing whitespace | Strict anchor placement and length limits |
| **Wildcard Namespaces** | `debug` (CVE-2017-20165) | Split pattern matching `\*` with unconstrained prefix | Simplified linear split without ambiguous greedy match |

---

## 5. Classification & Evidence Schema

```typescript
interface ReDoSFinding {
  ruleId: 'Y-REDOS-001';
  cwe: 'CWE-1333';
  verdict: 'CONFIRMED' | 'CANDIDATE' | 'CLEAN_WITHIN_SCOPE';
  confidence: 'HIGH' | 'MEDIUM';
  title: string;
  file: string;
  line: number;
  snippet: string;
  proofWitness: {
    pattern: string;
    ambiguityType: 'NESTED_QUANTIFIER' | 'OVERLAPPING_ALTERNATION' | 'ADJACENT_OVERLAP';
    ambiguousSubpattern: string;
    overlappingCharacterSet: string[];
    mitigationEvaluated: {
      isLengthBounded: boolean;
      hasLookaheadGuard: boolean;
      inputLengthGuarded: boolean;
    };
    complexityHypothesis: 'POTENTIAL_POLYNOMIAL' | 'POTENTIAL_EXPONENTIAL';
  };
}
```

---

## 6. Regression & Acceptance Test Matrix

The implementation must verify:
- **Positive Regressions:**
  * P5-033 (`tough-cookie` vulnerable): `CONFIRMED`
  * P5-041 (`cross-spawn` vulnerable): `CONFIRMED`
  * Synthetic nested repetition `(a+)+`: `CONFIRMED`
  * Overlapping alternation `(a|ab)+`: `CONFIRMED`
- **Negative Regressions (Must produce 0 alerts):**
  * P5-033 (`tough-cookie` patched with `{0,256}`): `CLEAN_WITHIN_SCOPE`
  * P5-041 (`cross-spawn` patched with `(?=\\*?)"`): `CLEAN_WITHIN_SCOPE`
  * Bounded repetition `a{1,10}`: `CLEAN_WITHIN_SCOPE`
  * Disjoint alternation `(cat|dog)+`: `CLEAN_WITHIN_SCOPE`
  * Safe email validation regex without nested quantifiers: `CLEAN_WITHIN_SCOPE`
