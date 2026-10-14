# Prospective Benchmark Custody, Blinding, and De-identification Plan V1

**Version:** 1.1.0-AUDITED  
**Security Level:** SEALED BENCHMARK PROTOCOL  
**Target Entities:** Independent Corpus Custodian, Engine Operators, Adjudication Reviewers  
**Current Realized State:** `PROTOCOL_COMMITTED` (Documentation committed; Custodian Appointment & Manifest Sealing PENDING)  

---

## 1. Precise Verification of Governance Realization States

To ensure complete scientific integrity, the actual implementation state of the prospective benchmark governance is certified below:

| Governance Milestone | Target Description | Current Realized State | Evidence & Notes |
|---|---|---|---|
| **PROTOCOL_DRAFTED** | Prospective evaluation specifications created | **COMPLETED** | `PHASE_Y_PROSPECTIVE_PROTOCOL_V1.md` written. |
| **PROTOCOL_COMMITTED** | Specifications committed to git version control | **COMPLETED** | Saved in `benchmark/phase_y_prospective/`. |
| **CUSTODIAN_APPOINTED** | Independent custodian designated | **PENDING** | Custodian entity not yet formally appointed. |
| **MANIFEST_SEALED** | 100 pairs + 100 controls manifest encrypted & sealed | **PENDING** | Prospective candidate corpus has NOT been harvested or sealed. |
| **ENGINE_HASH_SEALED** | Target engine SHA-256 registered | **PENDING** | Awaiting formal decision between v0.2.0 and v0.3.0. |
| **READY_FOR_EVALUATION** | All pre-execution gates passed | **NOT REACHED** | Benchmark cannot execute until all PRE gates are satisfied. |

---

## 2. De-identification & Leakage Prevention Protocol

A critical methodological risk in automated static analysis benchmarking is that target repositories can leak their identity to reviewers or heuristic engines through non-code metadata. The prospective benchmark enforces mandatory de-identification prior to workspace exposure:

### 2.1 Workspace Metadata Sanitization
Before a cloned target repository is exposed to the runner or reviewers:
1. **Package Manifest Stripping:** `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` are stripped of `name`, `author`, `repository`, `homepage`, `bugs`, and dependency package names.
2. **Git Provenance Isolation:** `.git/config` is stripped of remote URLs (`git remote remove origin`). Commit logs are redacted to remove author names and commit message text (only raw diffs and tree SHAs remain).
3. **Documentation Removal:** `README.md`, `CHANGELOG.md`, `LICENSE`, and `CONTRIBUTING.md` are deleted from the evaluated test worktree.
4. **Header Comment Stripping:** File header comments containing copyright notices, repository URLs, or author attribution are stripped from evaluated target files.

### 2.2 Output Masking & Finding Normalization
To prevent adjudication reviewers from inferring engine identities:
1. **Engine Masking:** Output JSONL/SARIF streams are relabeled as **Engine Alpha** and **Engine Beta**.
2. **Rule ID Normalization:** Custom engine rule IDs (e.g. `Y-PROTO-001`, `js/prototype-polluting-assignment`) are mapped to neutral standardized category codes:
   - `CAT-PROTO-01`: Prototype Pollution Vulnerability
   - `CAT-REDOS-01`: Regular Expression Denial of Service Vulnerability
3. **Snippet and Trace Standard:** Findings are rendered using standardized line numbers, snippets, and dataflow step tables.

---

## 3. Cryptographic Sealing Ceremony (Pre-Execution Invariant)

When the custodian is appointed and the corpus is selected:
1. The custodian computes:
   $$\text{Hash}_{\text{manifest}} = \text{SHA256}(\text{PROSPECTIVE_MANIFEST_GROUND_TRUTH.json})$$
2. The engine operator computes:
   $$\text{Hash}_{\text{engine}} = \text{SHA256}(\text{sentinel-y/v0.2/index.js})$$
3. Both hashes are recorded in a signed, immutable git commit tag (`prospective-v1-sealed`) on `sentinel-audit`.
4. Any deviation from these hashes permanently invalidates the evaluation.
