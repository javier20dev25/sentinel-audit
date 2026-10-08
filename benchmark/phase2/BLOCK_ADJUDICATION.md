# Adjudication Report: The 11 Phase 2A BLOCK Targets

**Campaign:** `PHASE2_REAL_WORLD_BENIGN_OSS`
**Evaluated Set:** 180 real-world open source npm packages
**Raw BLOCK Incidence:** 11 / 180 = **6.11%** (Wilson 95% CI: [3.45%, 10.61%])

---

## 1. Executive Adjudication Summary

A critical scientific distinction must be drawn between **BLOCK decisions** and **False Positives**:
A package categorized as "benign" in an open-source corpus may legitimately contain dangerous or risky code patterns (e.g., dynamic code compilation, arbitrary deserialization, or unpinned dependencies) that a production security policy *should* block.

Of the 11 BLOCK targets:

| Adjudication Category | Count | Effective Rate | Targets |
| :--- | :---: | :---: | :--- |
| **Justified High-Risk Block** | **3** | **1.67%** | `ejs@3.1.10`, `js-yaml@3.14.1`, `es5-ext@0.10.64` |
| **Policy / Supply-Chain Dependency Flag** | **3** | **1.67%** | `browserslist@4.23.0`, `picomatch@2.3.1`, `vinyl@2.2.1` |
| **Test Fixture Artifacts** | **1** | **0.56%** | `needle@3.3.1` (dummy test credentials) |
| **Pure Technical False Positive (FP)** | **4** | **2.22%** | `depd@2.0.0`, `fresh@0.5.2`, `morgan@1.10.0`, `source-map-support@0.5.21` |

### Key Metrics Post-Adjudication:
* **Raw-to-Decision Compression:** `5,020 raw candidates → 101 escalations (2.01%) → 11 BLOCK decisions (0.22%)`
* **Raw Candidate Non-Promotion Rate:** **97.55%** (4,897 / 5,020 suppressed or resolved without blocking)
* **True Decision FPR (Pure Technical FPs):** **2.22%** (4 / 180)
* **Broad Decision FPR (Technical FPs + Policy Flags):** **4.44%** (8 / 180)

---

## 2. Case-by-Case Technical Analysis

### A. Justified High-Risk Blocks (3 packages)

1. **`ejs@3.1.10`**:
   - *Findings:* Dataflow inspection flagged `EXPLOITABLE` taint reaching `eval()` / `new Function()`.
   - *Technical Reality:* EJS compiles arbitrary user-supplied template strings into executable JavaScript functions. This pattern is the exact mechanism of real-world Server-Side Template Injection (SSTI) exploits (e.g., CVE-2022-29078).
   - *Verdict:* **JUSTIFIED BLOCK**. Blocking EJS in an environment enforcing zero dynamic code generation is standard security posture.

2. **`js-yaml@3.14.1`**:
   - *Findings:* CLI / Oracle flagged `UNSAFE_EVAL` in `lib/js-yaml/type/js/function.js`.
   - *Technical Reality:* `js-yaml` 3.x natively includes the `!!js/function` type parser, which executes arbitrary code via `eval()` to reconstitute functions from YAML (famous historical RCE vector CVE-2013-4660).
   - *Verdict:* **JUSTIFIED BLOCK**. Safe production YAML parsers forbid this behavior.

3. **`es5-ext@0.10.64`**:
   - *Findings:* `LIFECYCLE_CURL_BASH` in `package.json` + `UNSAFE_EVAL` in `function/#/copy.js` and `object/unserialize.js`.
   - *Technical Reality:* Package contains aggressive postinstall lifecycle execution scripts alongside dynamic `Function` constructor arity manipulation.
   - *Verdict:* **JUSTIFIED BLOCK**. Enterprise supply chain gates routinely block unverified lifecycle script executions.

---

### B. Policy / Supply Chain Dependency Flags (3 packages)

4. **`browserslist@4.23.0`**, 5. **`picomatch@2.3.1`**, 6. **`vinyl@2.2.1`**:
   - *Findings:* Cloud engine flagged `DIRECT_URL_DEPENDENCY` (CRITICAL) in `package.json`.
   - *Technical Reality:* These packages specify direct git/HTTP URL dependencies in their manifests rather than versioned registry releases.
   - *Adjudication:* **POLICY-DEPENDENT FP**. While legitimate in open source, zero-trust enterprise policies reject unpinned direct URL dependencies to mitigate repo-hijacking risks.

---

### C. Test Fixture Artifacts (1 package)

7. **`needle@3.3.1`**:
   - *Findings:* CLI flagged `SECRET_HARDCODED_PASSWORD` in `test/basic_auth_spec.js`.
   - *Technical Reality:* Unit tests specify mock basic-auth credentials (`"user:pass"`). The scanner lacked a path-based test-directory exclusion.
   - *Adjudication:* **POLICY-DEPENDENT FP**. Easily remediable by scoping production scanners to non-test source trees.

---

### D. Pure Technical False Positives (4 packages)

8. **`depd@2.0.0`**:
   - *Findings:* CLI flagged `AGENT_RISK` for monkeypatching `process.on('deprecation')`.
   - *Adjudication:* **TRUE FP**. Benign diagnostic utility.

9. **`fresh@0.5.2`**:
   - *Findings:* CLI flagged `AGENT_RISK` on header parsing.
   - *Adjudication:* **TRUE FP**. Safe HTTP header validator.

10. **`morgan@1.10.0`**:
    - *Findings:* CLI flagged `UNSAFE_EVAL` in `compile()` format string generator.
    - *Adjudication:* **TRUE FP**. Standard logging format compilation.

11. **`source-map-support@0.5.21`**:
    - *Findings:* CLI/Oracle flagged `UNSAFE_EVAL` for stack trace rewriting.
    - *Adjudication:* **TRUE FP**. Runtime developer instrumentation.
