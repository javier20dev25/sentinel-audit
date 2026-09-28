# sentinel-audit

An audit orchestrator. It runs existing analyzers, records what each one
actually covered, refuses to report "clean" over checks that never executed,
and stops for a human before anything is called a vulnerability.

It does not detect vulnerabilities. It is the thing that keeps detection
honest.

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

```bash
node audit-runner.js doctor
node audit-runner.js preflight <repo> [<repo> ...]
node audit-runner.js audit <repo> --name <label>
node audit-runner.js report <expedienteDir>
node audit-runner.js adjudicate <expedienteDir> --candidate SAR-0001 \
    --disposition <DISPOSITION> --priority <P0|P1|P2|P3> --rationale "..."
```

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
