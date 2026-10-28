# sentinel-audit

An audit orchestrator. It runs existing analyzers, records what each one
actually covered, refuses to report "clean" over checks that never executed,
and stops for a human before anything is called a vulnerability.

It does not detect vulnerabilities. It is the thing that keeps detection
honest.


## Part of the Sentinel platform

| Product | Purpose | When to use |
|---------|---------|-------------|
| **[Sentinel CLI](https://github.com/javier20dev25/sentinel-cli)** | Local-first SAST, supply chain audit, build intelligence, skills/MCP for AI agents | Run locally, in CI, or as part of agent workflows. No account required for core scans. |
| **[Sentinel Audit](https://github.com/javier20dev25/sentinel-audit)** | Focused audit workflows (deps/PRs/CI) and reporting | Structured audits with tighter reporting/automation. |
| **[Sentinel Cloud](https://github.com/javier20dev25/sentinel-cloud)** | Web dashboard, team workflows, full-engine scans with pulses | When you need shared intelligence, collaboration, or the full engine. |
| **[Sentinel Oracle](https://github.com/javier20dev25/sentinel-oracle)** | Merge authorization/enforcement server (gate PR merges) | When you need to enforce "authorize before merge" with isolated enforcement. |

> **Tip:** If Sentinel Cloud is temporarily unreachable or you hit auth/connection issues, use the CLI directly (`sntnl scan`, `sntnl audit-deps`) — it works standalone without Cloud.

## Why this exists

Running seven security tools and concatenating their output produces a
number, and the number is meaningless without knowing what was checked. A
report that says "0 findings" is indistinguishable from a report where the
analyzer crashed, was skipped, or silently parsed nothing. Both look clean.

This runner exists so those two things can never look the same. Every finding
count travels with its coverage, and the verdict names what was not checked.

## The pipeline

```
preflight  ->  run tools  ->  validate health  ->  normalize
          ->  correlate  ->  adjudicate (human)  ->  report
```

`preflight` answers, before spending a byte: is there a disclosure channel,
is the language analyzable by something installed, how big is the real
analyzable surface, and what will it cost.

## Commands

### Interactive PR analysis

Running `sentinel-audit` opens a colored terminal menu and reports the active
GitHub CLI identity when available. GitHub identity is checked through the
authenticated `gh api user` endpoint. The PR workflow uses the current Git
remote automatically and begins listing open pull requests without requiring
an extra confirmation keystroke. When no remote is available, choose a
repository from the authenticated account's repository list.

The menu, repository and PR selectors, engine choice, findings, and saved
reports render in bordered panels. Findings use severity-colored panels and
show a concise snippet; the full evidence remains in the execution report.
The stage map uses a slower live spinner and a bordered status view so progress
is readable during longer specialist runs. Set `NO_COLOR=1` for plain output.

Menu navigation is numbered throughout: `0` or Enter backs out of selection
screens, and Enter at the main menu exits. Options 4 and 5 let you choose a
repository and recent commit from GitHub, then run an audit or preflight on an
isolated temporary checkout. Option 6 lists saved local executions so reports
can be rendered without typing filesystem paths. After key management or an
audit, the CLI returns to the main menu. The responsibility notice is available
from option 7.

The guided PR workflow labels the deterministic diff scan as **Sentinel Audit
Lite**. It then pins the PR head SHA, creates a temporary checkout, passes the
Lite signals into the Sentinel Audit routing pipeline, runs justified local
specialists that are installed, correlates their findings, and prints a stage
map. The execution directory contains the full evidence and report. Missing
specialists, unrouted signals, failed stages, and unknown coverage are shown as
gaps with reasons; they are never represented as a clean scan.

Saved Sentinel Cloud keys do not mean a pulse was used. The guided PR menu
offers a hosted pulse only when hosted policy is enabled, the cloud client and
`SENTINEL_CLOUD_URL` are configured, and a key is available. Selecting that
option explicitly sends the pinned PR checkout to Sentinel Cloud; the local
Lite diff result remains labeled separately. Otherwise, the menu lists the
missing prerequisites and uses the local path. The responsibility notice is
available from menu option 7 rather than printed on every startup.

### Windows launcher

The repository includes `sentinel-audit.cmd`, a dependency-free launcher for
PowerShell and Command Prompt. Add the checkout to the user PATH once, then
open a new terminal:

```powershell
$auditRoot = 'C:\Users\sleyt\sentinel-audit'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$auditRoot*") {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$auditRoot", 'User')
}
```

Verify with `sentinel-audit --help`. The launcher requires Node.js 20 or
newer and does not elevate privileges or install anything globally.

The terminal workflow remains available through `sentinel-audit` or
`sentinel-audit interactive`. Use `sentinel-audit doctor` for a machine-readable
readiness report. The menu helps select a workflow but does not replace reading
the report or human adjudication.

### Local evidence dashboard

Run `sentinel-audit web` to start the browser console at
`http://127.0.0.1:4317`. It binds to loopback only and does not open a browser
automatically. The dashboard requires Node.js 22.5 or newer for the built-in
SQLite module; the terminal commands continue to support Node.js 20 or newer.
Set `SENTINEL_AUDIT_WEB_PORT` to change the local port.

The dashboard enumerates repositories and open PRs through the active GitHub
CLI session. Each PR offers a local Lite scan and, only when hosted policy,
client, URL, and a saved key are ready, an explicit Sentinel Cloud Pulse. Both
paths pin the PR head to its full SHA and run Sentinel Audit's own pipeline;
Pulse sends the pinned checkout to the configured Sentinel Cloud endpoint.
Specialists and their coverage states appear independently. The local evidence
map distinguishes completed, partial, failed, unavailable, and unrun stages.
An optional retry is limited to specialists already justified by the saved
signal route; tools that the route did not select are not silently forced.

Each completed scan is stored in the Audit-only SQLite database at
`~/.sentinel-audit/audit.sqlite` (on Windows, under the user's home directory).
The interface provides scan, finding, and stage tables, a long-cell modal,
severity/source/file/date summaries, and JSON export. The report records a
SHA-256 digest for the scan body and a separate digest for the exact PR diff;
the body digest is computed over canonical serialized JSON before its
`integrity` field is added. These are content references, not signatures or
attestations from GitHub.

The API-key panel uses the existing Sentinel Audit local key store, masks tokens
in every listing, and never returns a token to browser code. Removing a key
here deletes its local copy only; it does not revoke it server-side in Sentinel
Cloud. Store and revoke credentials through the Sentinel Cloud account when
permanent invalidation is required. The local dashboard has no remote login or
multi-user protection and should remain bound to the current device.

Tool inventory states distinguish an executable found on the host, an executable
blocked by a host runtime guard, and a binary not found on `PATH` or configured
paths. “Not found” is not a claim that the package cannot exist in an unsearched
location. Analytics use a donut for severity composition, ranked horizontal bars
for engine/source counts, a ranked list for affected files, tiles for categories,
and an SVG timeline for scan dates.

Coding agents can follow the optional [`sentinel-audit` skill](./skills/sentinel-audit/SKILL.md)
for health checks, pinned scope, coverage reporting and human-led adjudication.

```bash
node audit-runner.js interactive
node audit-runner.js doctor
node audit-runner.js preflight <repo> [<repo> ...] --commit <sha>
node audit-runner.js run <repo> --commit <sha> --routing file|directory|repo
node audit-runner.js route <executionDir> --routing file|directory|repo
node audit-runner.js specialists <executionDir> [--only codeql,semgrep]
node audit-runner.js report <executionDir>
node audit-runner.js cleanup <executionDir>
node audit-runner.js adjudicate <executionDir> --candidate SAR-0001 \
    --disposition <DISPOSITION> --priority <P0|P1|P2|P3> --rationale "..."
```

### Mapa de ejecución en terminal

Los comandos `run` y `scan` muestran un mapa en vivo en stderr: preflight,
checkout fijado al commit, motor seleccionado, enrutamiento, trabajos especialistas,
correlación, triage y limpieza. Los estados y herramientas provienen del pipeline;
no se estiman porcentajes. Los analizadores paralelos muestran su estado de cola,
ejecución y finalización individual. Al terminar queda una vista estática del
resultado junto al resumen de salida.

El mapa usa color y redibujado solo en una terminal interactiva. `NO_COLOR`,
`TERM=dumb`, CI, `--json` y `--quiet` evitan secuencias ANSI o animación; JSON
permanece limpio en stdout y el progreso interactivo va por stderr. En modo
`--provider cloud` se distingue el motor alojado; la API no ofrece progreso de
sus componentes internos, así que el mapa solo informa el inicio y el resultado
agregado del motor.

Consulte [la guía del mapa de ejecución](./docs/terminal-progress.md) para leer
los estados y el alcance de cada etapa.

`audit` and `scan` remain aliases for `run`. Each new execution receives a
unique directory under `out/<repo>/<execution-id>/`; raw evidence is written
before normalization and is not reused across runs. `identity.json` pins the
target commit/tree and records worktree state, engine revision/hash, audit
source hashes, specialist versions, and routing/config hashes. A dirty target
checkout or a requested SHA that differs from `HEAD` fails preflight.

Routing policy is in `config/policies.json`. `file` is the current default;
`directory` groups promoted files by parent directory, and `repo` selects the
whole checkout. Repository-wide tools such as CodeQL/Trivy/OSV are explicitly
recorded as repo-level jobs and are not represented as scoped by Cloud.
`--only` and `--skip` can narrow a justified specialist set; skipped jobs remain
coverage gaps. Unpromoted files mean “not selected for this stage,” never
“safe.”

Coverage counters are only numeric when an analyzer provides a real denominator.
Otherwise the artifact carries `coverageKnown=false`, `coverageUnknown=true`,
and `ENGINE_COVERAGE_UNMEASURED`; an execution-complete flag is not a coverage
claim. Candidate records retain signal, promotion, job, specialist-finding and
correlation IDs. CodeQL's memory setting is recorded as a requested budget, not
as measured peak RAM.

Exit codes: `0` complete with no blocking candidate; `1` candidate(s) under the
configured policy; `2` incomplete/degraded execution; `3` preflight or
configuration failure; `4` unrecoverable infrastructure/tool failure.

The primary sensor is the local Sentinel Cloud worker engine configured in
`config/tools.json`. The runner calls its scanner module directly in local mode;
it does not call the hosted service or Sentinel Purple. Scanner parse coverage
is currently unmeasured, so a zero-signal result is never a clean claim.

### Candidate fields that are not verdicts

Two fields on a candidate are workflow bookkeeping. Neither is read by any
verdict, neither changes `reportable`, and neither can close or promote a
finding. They are stated here because a field that changes nothing is easy to
mistake for one that decides something.

| Field | Values | Meaning |
|---|---|---|
| `investigationPriority` | `P0`–`P3`, unset | how soon a human should look |
| `reviewState` | `UNREVIEWED`, `REVIEWED` | whether anyone has adjudicated it |

`PLAUSIBLE + UNREVIEWED` means the tool produced it and nobody has looked.
`PLAUSIBLE + REVIEWED` means an analyst looked and kept the hypothesis. Without
that distinction an untouched backlog is indistinguishable from a triaged one.

## Tools orchestrated

| Tool | Role | Authority |
|---|---|---|
| Sentinel Cloud worker engine | primary behavioral signals | signal only; coverage currently unmeasured |
| CodeQL | dataflow / reachability | corroborating |
| Semgrep | pattern semantics | corroborating |
| Bandit | Python sink semantics | corroborating |
| ShellCheck | shell lint | lint only, never a taint claim |
| Trivy | SCA + secrets | contextual |
| OSV | SCA | contextual |

A tool is one of three things, and the distinction is load-bearing:

- **corroborating** — can promote a signal to a candidate
- **signal only** — can never promote anything on its own
- **contextual** — informs a human, promotes nothing

## Invariants

These are the reasons the code is shaped the way it is. Each one exists
because its absence produced a wrong answer.

1. **A finding count is never reported without coverage.**
   `tool error != 0 findings`, `partial != clean`, `unsupported != clean`,
   `skipped != clean`, `scope exclusion != silent discard`.

2. **SENTINEL_SIGNAL != CANDIDATE != CONFIRMED_ISSUE.**
   Tool confidence never decides exploitability. Only `adjudicate` does, and
   only a human calls it.

3. **A skipped tool is a coverage gap, not a clean result.**
   A tool that never ran cannot support a clean claim. `NOT_APPLICABLE` is
   different: Bandit on a JavaScript repo is not a gap, OSV without a lockfile
   is. See v1.1 below, where this was wrong.

4. **Git is the source of truth** for `SECURITY.md`, `LICENSE`, commit and
   tree. A filesystem heuristic cannot grant or deny a disclosure channel.

5. **A retired channel is not a channel.** A policy that closes a program
   does not thereby offer it. A CNA escalation address is a fallback, not the
   maintainer's route. See v1.2 below, where this was wrong.

6. **Every candidate preserves its evidence**: repo, commit, tree, tool,
   rule, file, line, snippet, source, sink, path, controls and corroborating
   signals. A reviewer must never need to re-clone the target to judge it.

7. **Publication is unconditionally forbidden.** No push, no PR, no issue, no
   email, no automatic disclosure. Fixes and drafts stay local.

8. **Target code is never executed**, built, tested, or installed.

9. **The runner orchestrates. It does not re-implement detection.**

## Verdicts

| Verdict | Meaning |
|---|---|
| `CLEAN_WITH_FULL_COVERAGE` | every applicable tool completed, nothing open |
| `CLEAN_WITH_LIMITATIONS` | nothing open, but some tool had reduced coverage |
| `CANDIDATES_FOUND` | something needs human adjudication |
| `PARTIAL_ANALYSIS` | at least one applicable tool did not complete |

Per tool: `SUCCESS`, `PARTIAL`, `ERROR`, `UNSUPPORTED`, `SKIPPED`,
`NOT_APPLICABLE`.

`verdict` and `analysisState` are separate fields on purpose. Collapsing them
is how a run with dead tools gets called clean, or how a run with twelve real
candidates gets filed under "degraded" and buried.

## Dispositions

`CONFIRMED_SECURITY_ISSUE`, `STRONG_SECURITY_CANDIDATE`,
`PLAUSIBLE_SECURITY_ISSUE`, `BENIGN`, `TOOLING_INTENT`, `FALSE_POSITIVE`,
`DUPLICATE`, `ALREADY_MITIGATED`, `OUT_OF_SCOPE`, `UNRESOLVED`,
`STATIC_ONLY_LIMITATION`.

## Verification

`tools/determinism.js` asserts that two runs over the same pinned commit
produce identical evidence once timestamps, paths and wall-clock are removed.

```bash
node audit-runner.js audit <repo> --name runA
node audit-runner.js audit <repo> --name runB
node tools/determinism.js out/runA out/runB
```

A nonzero exit means real nondeterminism, which must be explained rather than
tolerated.

## Freeze history

| Tag | Commit | What it froze, or what was wrong with it |
|---|---|---|
| `audit-runner-v1-freeze` | `3819cc0` | Initial freeze. **Known wrong**, kept for the record. |
| `audit-runner-v1.1-freeze` | `ab60f15` | A skipped tool no longer counts as clean. |
| `audit-runner-v1.2-freeze` | `16b1dab` | Retired channels and CNA fallbacks are not vetted channels. |
| `audit-runner-v1.3-freeze` | `6d09016` | A finding closed by an analyst no longer counted as open, so a triaged target could be reported clean. |
| `audit-runner-v1.4-freeze` | `4e0c267` | Investigation priority, as a field no verdict reads. |
| `audit-runner-v1.5-freeze` | this commit | Historical freeze; its Purple opt-out behavior was removed when wiring the direct Cloud worker engine. |

v1 and v1.1 are both wrong in ways that produced a false clean claim. They are
not deleted. A freeze that gets quietly rewritten is worse than one that keeps
its mistakes visible, because the mistakes are the argument for the invariants
above.

Both defects were found by running the campaign, not by testing. The first
audit target (`fastify/fastify`) hit both. The v1.3 defect was found the same
way: after adjudicating all three of `axios/axios`'s candidates, the runner
still reported them as open, and a target with nothing left to do looked like a
target with work outstanding.

## Verified results

| Target | Commit | Verdict | Candidates | Coverage gap |
|---|---|---|---|---|
| `fastify/fastify` | `c3051e5b60c0` | `PARTIAL_ANALYSIS` | 0 | OSV skipped, no lockfile |
| `expressjs/express` | `9a34acf03cb8` | `PARTIAL_ANALYSIS` | 0 | OSV skipped, no lockfile |
| `nestjs/nest` | `b58554ea5857` | `CLEAN_WITH_FULL_COVERAGE` | 1 adjudicated `TOOLING_INTENT` | none |

Zero confirmed vulnerabilities. `PARTIAL_ANALYSIS` on the first two is
correct, not a failure: neither ships a lockfile, so the SCA class of checks
could not run, and the runner declines to call that clean.

## Known limitations

- **Sentinel emits no line numbers.** Its `commensal` mode reports findings
  at file granularity only. Every signal is preserved (zero loss), but
  Sentinel-only observations are not triageable to a line. This is a Sentinel
  limitation; the runner does not modify Sentinel.
- **SCA needs a lockfile.** Targets without one are `PARTIAL_ANALYSIS` by
  construction, even when everything else is clean.
- **ShellCheck is lint.** A clean ShellCheck run says nothing about injection.
- Static analysis only. No dynamic testing, no exploit execution.
- Correlating a Python finding with JavaScript tooling is not attempted;
  the pipeline treats cross-language corroboration as unproven.

## Layout

```
audit-runner.js        CLI
config/tools.json      tool paths, query suites, memory
config/policies.json   budgets, coverage rules, disclosure policy
lib/core.js            envelopes, verdicts, git helpers, coverage
workflow/preflight.js  gates, disclosure and license detection, cost
workflow/audit.js      the pipeline
adapters/index.js      one adapter per tool
correlate/index.js     dedup, candidates, adjudication, audit verdict
reports/expediente.js  Markdown report
tools/determinism.js   the determinism assertion
tools/verdict-matrix.js  which dispositions may claim clean
out/                   run output, gitignored
```
