# Contributing to Sentinel Audit

Thank you for your interest in contributing to Sentinel Audit.

Sentinel Audit is a security orchestrator that joins Sentinel Cloud intelligence with specialized open-source analyzers (CodeQL, Semgrep, Trivy, OSV, Bandit, ShellCheck) over immutable repository commits.

## Development Setup

1. **Prerequisites**:
   - Node.js >= 20.0.0
   - Git >= 2.30.0

2. **Installation**:
   ```bash
   git clone https://github.com/sentinel-security/sentinel-audit.git
   cd sentinel-audit
   ```

3. **Verify Environment**:
   ```bash
   node audit-runner.js doctor
   ```

4. **Running Tests**:
   ```bash
   npm test
   ```

## Contribution Principles

- **Zero Unverified Claims**: Absence of output from an analyzer is a coverage gap or failure, never a clean security finding.
- **Fail-Closed on Surprises**: Security tools must never swallow crashes or timeouts silently.
- **Deterministic Artifacts**: Execution outputs and expedientes must be reproducible for any immutable target commit.
- **Strict Privacy**: API tokens and private credentials must never be persisted in artifacts, logs, or error messages.

## Submitting Pull Requests

1. Fork the repository and create your feature branch (`feat/my-feature` or `fix/issue-description`).
2. Run test suites and verify pre-publication checks (`node scripts/public-release-audit.js`).
3. Commit with concise, conventional commit messages.
4. Open a Pull Request describing your changes, test evidence, and motivation.
