---
name: sentinel-audit
description: Guide a human or coding agent through Sentinel Audit preflight, pinned-commit analysis, evidence review, and human adjudication. Use when asked to run a structured multi-tool audit or interpret an Audit execution.
---

# Sentinel Audit agent workflow

Sentinel Audit is a terminal-first orchestrator. It records tool health,
coverage, raw evidence and candidate signals; it does not confirm a
vulnerability by itself. Keep a human responsible for deciding whether a
candidate is valid and whether to disclose it.

## Before an execution

1. Run `sentinel-audit doctor --json` (or `node audit-runner.js doctor --json`).
   Report unavailable tools and hosted/local configuration as coverage gaps.
2. Pin the exact full 40-character commit SHA. Do not audit a moving branch.
3. Run `sentinel-audit preflight <repo> --commit <sha> --json` and inspect the
   result. Stop if preflight says `SKIP`; do not describe a skipped execution as
   clean.
4. Confirm the requested scope: `file`, `directory`, or `repo`. Use `repo` only
   when a repository-wide question or a repository-level specialist warrants it.
5. For interactive use, run `sentinel-audit interactive`; the menu asks for a
   pinned SHA and a confirmation before starting an audit.

## Run and report

Run `sentinel-audit run <repo> --commit <sha> --routing <scope> --json` only
after the user asked for the analysis. Do not install packages, run project
builds, or execute target code as part of the audit. Preserve the execution
directory and review `identity.json`, tool health, coverage gaps, raw evidence,
and candidate-to-source links.

Use `sentinel-audit report <execution-dir> --json` to regenerate a report.
Never call zero findings “safe” if coverage is unknown, a tool failed, or a
candidate is still open. Do not change candidate disposition, severity or
priority to force a clean result. Human adjudication must include a rationale.

## Reporting language

- Separate tool-produced evidence from your interpretation.
- Say which analyzers ran, which did not, and what scope they covered.
- Describe candidates as unconfirmed until a human validates impact and
  exploitability.
- Do not submit, email, comment on a PR, or publish a disclosure unless the
  human explicitly asks.
