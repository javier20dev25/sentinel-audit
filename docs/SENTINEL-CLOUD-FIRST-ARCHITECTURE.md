# Sentinel Cloud — Architecture Overview

Sentinel Audit is a security orchestrator that works in two modes:

## 1. Hosted Mode (`--cloud`)

The primary production mode. Source archives are submitted to **Sentinel Cloud** via the `@sentinel/cloud-client` package. The cloud worker processes each archive through the full Sentinel engine and returns a structured result envelope.

```
sentinel-audit run --repo <path> --commit <sha> --cloud
        │
        ▼
   workflow/archive.js
   Pack repository into deterministic POSIX ustar .tar.gz
        │
        ▼
   @sentinel/cloud-client
   submitRepositoryScan(archive, token, baseUrl)
        │
        ▼   HTTPS
   Sentinel Cloud API
   POST /api/scan/repository
        │
        ▼
   Supabase Storage (repository-scan-uploads)
   + repository_scans row (PENDING)
        │
        ▼
   Sentinel Worker (Render)
   claim → extract → scan → complete
        │
        ▼
   Result envelope (signals, coverage, status)
        │
        ▼
   @sentinel/cloud-client
   waitForRepositoryScan(scanId)
        │
        ▼
   sentinel-audit (Routing → Specialists → Report)
```

### Configuration

| Variable              | Description                            |
| --------------------- | -------------------------------------- |
| `SENTINEL_CLOUD_URL`  | Base URL of the Sentinel Cloud instance |
| `SENTINEL_CLOUD_API_TOKEN` | API token obtained from Sentinel Cloud  |

Both are read from environment variables. The token is never written to any artifact or log.

## 2. Local Mode (`--provider local`)

For operators who have the Sentinel Cloud worker engine installed locally (e.g., enterprise on-prem deployments), the engine can be pointed to via `config/tools.json`. In this mode the engine runs in-process without a network round-trip.

## Signal Flow

```
Sentinel Engine Output
        │
        ▼
   adapters/normalize.js
   Normalize signals to uniform envelope
        │
        ▼
   workflow/audit.js
   Route ACTIONABLE_SIGNAL → specialists
        │
        ▼
   Specialists (CodeQL, Semgrep, Trivy, OSV, Bandit, ShellCheck)
   Verify signals in their domain
        │
        ▼
   correlate/index.js
   Build candidate set with evidence
        │
        ▼
   reports/expediente.js
   Render REPORT.md + expediente.json
```

## Artifact Isolation

- Execution artifacts are written to `out/<name>/<executionId>/`.
- Source archives are zeroed immediately after upload.
- Worker cleans up the uploaded archive after completing or failing.
- The `out/` directory is excluded from npm publish.

## Supported Specialists

| Tool        | Purpose                      | Language(s)        |
| ----------- | ---------------------------- | ------------------ |
| CodeQL      | Dataflow / taint analysis    | JS/TS, Python, ... |
| Semgrep     | Pattern matching             | Any (custom rules) |
| Trivy       | SCA / secrets / misconfig    | Any                |
| OSV         | Open-source vulnerability DB | Any (via lockfile) |
| Bandit      | Python sink analysis         | Python             |
| ShellCheck  | Shell lint                   | Bash / sh          |
