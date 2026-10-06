# Sentinel Audit v1 - Acceptance

**Status: ACCEPTED for internal use, with the limitations recorded below.**

This document records the real-execution acceptance of Sentinel Audit v1 against five
pinned public repositories. Every number below comes from an executed run, not from a
design claim. Nothing here was edited after the fact: where a run was wrong, the
defect and the fix are recorded in "Defects found during acceptance" instead of
quietly correcting the result.

No commit, push, pull request, issue or external publication was made. The target
repositories were treated as read-only. Sentinel Cloud, Purple and Oracle were not
modified.

## 1. What was executed

Five repositories, each pinned to a full 40-character commit, each verified before and
after the run:

| Repository | Pinned commit | Checkout |
|---|---|---|
| express | `9a34acf03cb818ff3f8bc40e44176e277a25cbb9` | read-only, pre-existing |
| fastify | `bc25b7499acedb803ef3cef644d0d56cf4e7c725` | read-only, pre-existing |
| svelte | `f90853565966bc0bab57c99fe7d669a91bef0f4c` | read-only, pre-existing |
| flags | `c3026fe78b527f8c4300f444751ef4f9325db50e` | read-only, pre-existing |
| swr | `9ed1240a4cf799e316a793c22c6800cc6482d389` | read-only, pre-existing |

Each run used the managed-clone path: the orchestrator cloned the pinned commit into a
disposable worktree, recorded the resolved commit and tree, asserted the worktree was
clean, and removed the worktree afterwards. The source checkouts were never modified.

## 2. Acceptance results

Two full acceptance passes were run. The first is the baseline that exposed the defects in
section 4; the second is the P0 closure re-run, executed after the routing and target
identity work. Both are recorded, because a result that only appears after the fix is not
evidence that the fix was needed.

All ten runs reached `pipelineStatus: COMPLETE` with `cleanup: CLEAN`.

| repo | pin verified | verdict | analysisState | canClaimClean | candidates | observations | cleanup | exit |
|---|---|---|---|---|---:|---:|---|---:|
| express | yes | LIMITED_ANALYSIS | LIMITED_COVERAGE | false | 0 | 11 | CLEAN | 2 |
| fastify | yes | LIMITED_ANALYSIS | LIMITED_COVERAGE | false | 0 | 31 | CLEAN | 2 |
| svelte | yes | CANDIDATES_FOUND | LIMITED_COVERAGE | false | 18 | 132 | CLEAN | 1 |
| flags | yes | CANDIDATES_FOUND | LIMITED_COVERAGE | false | 2 | 88 | CLEAN | 1 |
| swr | yes | CANDIDATES_FOUND | LIMITED_COVERAGE | false | 1 | 16 | CLEAN | 1 |

The P0 closure re-run reproduced every one of those counts exactly. Per-tool outcome for
the closure run, including the exact resolved version of every binary:

| repo | sentinel (Cloud) | codeql | semgrep | trivy | osv | targets | absolute targets |
|---|---|---|---|---|---|---:|---:|
| express | PARTIAL 152 | PARTIAL 5 | PARTIAL 16 | PARTIAL 0 | SKIPPED (no lockfile) | 50 | 0 |
| fastify | PARTIAL 275 | PARTIAL 0 | PARTIAL 107 | PARTIAL 0 | SKIPPED (no lockfile) | 142 | 0 |
| svelte | PARTIAL 292 | PARTIAL 22 | PARTIAL 20 | PARTIAL 0 | PARTIAL 41 | 81 | 0 |
| flags | PARTIAL 435 | PARTIAL 5 | PARTIAL 14 | PARTIAL 17 | PARTIAL 35 | 125 | 0 |
| swr | PARTIAL 139 | PARTIAL 7 | PARTIAL 2 | PARTIAL 13 | PARTIAL 51 | 61 | 0 |

`absolute targets` is the count of routing targets persisted as absolute paths. It is
zero in every repository, which is the direct evidence that the target identity is now
repository-relative.

**The two OSV counts changed and the change is not a regression.** OSV was 25 on flags
and 45 on swr in the baseline, and is 35 and 51 in the closure run. Every other tool
reproduced its baseline count exactly. OSV queries a live advisory database, so its result
depends on the day it runs. This is recorded as an observed fact rather than smoothed
over, and it is a reminder that a network-backed scanner is not reproducible in the way a
pinned local engine is.

`SKIPPED` for OSV is not a failure and not a clean result. Those two repositories contain
no lockfile at the pinned commit, so a software-composition analysis has nothing to
resolve; the envelope is `notApplicable` and the preflight still reports the SCA
coverage gap. This was verified against the checkouts directly rather than trusted:
`express` and `fastify` genuinely have no lockfile, and the three repositories marked
`PARTIAL` do.

### Why no run can claim clean

`canClaimClean` is `false` in all five runs, and that is the correct outcome rather than
a conservative default. The Sentinel Cloud engine reports `coverageKnown: false`, so the
audit has no denominator proving the repository was fully parsed. A repository with
zero candidates and unknown coverage is a *limited* result, not a clean one. The two
repositories that produced no candidates (express, fastify) therefore exit `2`, not `0`.

### Exit codes observed

| Code | Meaning | Repos |
|---:|---|---|
| 0 | clean, complete coverage | none (no run reached a clean claim) |
| 1 | candidates found | svelte, flags, swr |
| 2 | degraded or limited coverage, no candidates | express, fastify |
| 3 | preflight or configuration failure | none |
| 4 | infrastructure failure | none |

No run exited `0`. The product has therefore never demonstrated a clean claim in
acceptance, and the report format is honest about that.

## 3. Candidate quality

The 21 candidates across the three repositories were inspected, not just counted. The
Svelte set, the largest, breaks down as:

| Rule | Count | Example location |
|---|---:|---|
| `js/polynomial-redos` | 6 | `packages/svelte/src/reactivity/media-query.js:44` |
| `sentinel.javascript.security.detect-child-process` | 4 | `playgrounds/sandbox/scripts/download.js:115` |
| `js/http-to-file-access` | 2 | `playgrounds/sandbox/scripts/download.js:792` |
| `js/redos` | 2 | `packages/svelte/src/compiler/phases/1-parse/index.js:84` |
| `js/bad-tag-filter` | 2 | compiler tag handling |
| `sentinel.javascript.security.audit.insecure-http-url` | 1 | `playgrounds/sandbox/ssr-dev.js:41` |
| `js/file-system-race` | 1 | filesystem access |

These are recognisable, real findings in real code paths, and they carry the full
correlation chain: Cloud signal id, route, job id, specialist finding id. Several sit
under `playgrounds/`, which the policy treats as non-production *by path hint*; they are
still promoted because the classifier found no stronger scope signal, which is a
deliberately conservative choice (over-report a demo file rather than silently drop it).

The known precision limit from the routing calibration is unchanged and is not a v1
blocker: several `playgrounds/` and `examples/` findings are non-production code that
Cloud promoted because it has no path-exclusion concept. A future policy revision can
add a non-production penalty; v1 does not claim the precision has been solved.

## 4. Defects found during acceptance

Sixteen real defects were found by running the product rather than by reading it. Each
is listed with the symptom an operator would have seen.

1. **Semgrep could never load its own ruleset.** The scan runs with the audited
   repository as its working directory, so the relative config path resolved against
   the wrong root and every Semgrep run degraded to zero findings. Fixed by resolving
   vendored rulesets to absolute paths.
2. **`--offline` is not a valid Semgrep flag.** Passed through verbatim, the engine
   refused to start. Removed.
3. **Semgrep rule ids changed with the checkout path.** Rule identity was derived from
   the config file path, so the same rule produced a different id on every machine and
   cross-run correlation silently failed. Fixed by normalising to the `sentinel.`
   namespace and verifying that vendored rules declare it.
4. **One bad target zeroed an entire Semgrep scan.** A single unreadable path made the
   adapter give up on the whole file set and report success with zero findings, which
   reads exactly like a clean result. Targets are now validated before the scan and
   rejections are reported in the envelope.
5. **The cleartext-URL rule was badly imprecise.** The original pattern fired 17 times
   across the express repository, none of them real. It also matched https URLs, loopback
   addresses and reserved documentation hosts. Rewritten to require a quoted `http://`
   literal pointing at a non-reserved host. Express now returns 0, and a fixture still
   produces exactly 1 true positive.
6. **CodeQL was invoked in the wrong order and could not create its database.** The
   parent directory was not created and the create/analyze/finalize sequence was wrong,
   so every CodeQL run failed after two minutes of work. Fixed and verified end to end.
7. **Trivy secret findings carried no location.** The adapter read `Secrets[].Target`,
   which Trivy 0.74 leaves empty, so a real hardcoded secret was reported without a file
   or line. Now falls back to the enclosing result target.
8. **Tool availability was silently dropped from envelopes.** The envelope builder did
   not carry the probe result, so a report could state `UNKNOWN` for a version that had
   actually been resolved. Propagated.
9. **The version probe produced false `INVALID`.** A tool that printed its version while
   exiting non-zero was marked unavailable, and an unavailable tool quietly degrades
   coverage. The probe now accepts version output, records the anomaly, retries once and
   scales the timeout.
10. **A retry destroyed evidence for tools it never re-ran.** The specialist stage emits
    a `SKIPPED` placeholder for every non-selected tool, and the retry assigned the whole
    result map over the expediente. Retrying Semgrep replaced a good CodeQL `PARTIAL`
    envelope with `SKIPPED`. A retry now touches only the tools it was asked to re-run.
11. **A retry rewrote no evidence files at all.** `specialist-jobs.json` was never
    refreshed and the `SPECIALISTS` stage kept the original timestamp, so the execution
    directory contradicted its own expediente. Both are now updated, and the job ledger
    is deduplicated by tool.
12. **A retry could never produce findings.** Routing targets are absolute paths into
    the original worktree, which cleanup had already deleted, so all 50 targets failed
    with `ENOENT` and the retry reported a scan that never happened. The adapter failed
    closed and recorded all 50 rejections, but the retry was useless. Targets are now
    rebased onto the attempt's worktree. Verified: a retried Semgrep reproduces its
    original 16 findings exactly, and the untouched CodeQL evidence survives.
13. **A retried run lost its raw evidence.** Specialist raw output was written into the
    attempt directory, which cleanup then deleted, so the retained artifact was the stale
    one from the first run. Raw output now lands in the execution directory, and process
    records are named per attempt so a retry keeps the history instead of overwriting it.

Two further defects were found in the OSV adapter (items 14 and 15), and one in the
repository inventory (item 16). All three were fail-open: they made the product look
healthier than it was.

14. **`offline: true` guaranteed failure.** OSV was configured for offline mode on a host
    with no seeded OSV database, so it could never resolve a single package. The default
    is now an online query; the offline flag is documented as requiring a seeded database.
15. **A successful OSV scan was reported as a tool error.** osv-scanner exits `1` to mean
    "vulnerabilities found" and `0` for clean; real failures are `128` and above. The
    adapter treated any non-zero exit as a failure, so 41 real vulnerabilities in Svelte
    and 45 in SWR were published under a red `ERROR` status with no explanation. Fixed,
    with a regression test.
16. **SCA was silently skipped on the repository with the largest lockfile.** The
    inventory applied the `maxFileBytes` size guard (512 KB) *before* deciding whether a
    file was a lockfile. Flags has a 779 KB `pnpm-lock.yaml`, so it was dropped as
    "oversized", the repository was reported as having no lockfile, and OSV was marked
    `NOT_APPLICABLE` instead of running. This is a fail-open defect with the worst
    possible direction: dependency risk concentrates in large lockfiles, and that is
    exactly where the tool stopped looking. Presence detection now runs before the size
    guard; Flags now yields 25 vulnerabilities, and a regression test pins the behaviour.

`npm test` grew from 23 to 29 tests during this work; the retry rebase, the OSV exit
semantics and the oversized-lockfile detection are covered by regression tests so they
cannot silently regress. The suite has since grown to 66 tests during the P0 closure
pass described in section 5.1.

## 5. Defects deliberately left open

These are known, understood, and recorded rather than hidden.

- **`npm test` covers the orchestrator unit surface plus three dedicated suites.**
  `test/orchestrator.test.js` holds the original unit tests; `test/routing-e2e.test.js`
  drives a real specialist through all three routing modes;
  `test/resilience.test.js` covers integrity, links, interrupts, disk, network and
  concurrency; `test/outcomes.test.js` covers the four specialist outcomes. Section 6
  is the honest accounting of what is still unverified.
- **CodeQL and Semgrep report no parsed-file denominator.** Both engines are therefore
  `PARTIAL` by construction even when they complete successfully. This is a property of
  the tools, and the product reports it instead of claiming full coverage.
- **The Sentinel Cloud engine is local and pinned.** Coverage remains `PARTIAL` and
  `coverageKnown: false` across every repository. Nothing in v1 can change that without a
  change to Sentinel Cloud, which is out of scope here.
- **Findings keep absolute file paths.** Routing *targets* are now repository-relative,
  but an individual finding records the absolute path the tool reported, because the
  snippet, containment and manifest logic all operate on it. This is a portability
  limitation of stored evidence, not a routing one.
- **`rebaseTargets` remains for backwards compatibility.** Executions persisted by
  earlier versions stored absolute targets against a worktree that has since been
  removed, so retry still rebases them. New executions never need it.

### 5.1 Defects closed in the P0 closure pass

Recorded because the history matters, not because they are still open.

- **`SEMGREP_TARGET_DIRECTORIES_REJECTED` — closed.** `usableTargets` now accepts a
  regular file, a directory or the repository root, and the three routing modes are proven
  end to end against a real Semgrep binary in `test/routing-e2e.test.js`. The earlier unit
  test asserted the broken behaviour and was rewritten, because it encoded the defect.
- **Routing targets stored as absolute paths — closed.** Targets are persisted as
  repository-relative POSIX identities, and the repository root is `.`. Resolution against
  the current execution happens at use time through `workflow/paths.js`. Verified on all
  five acceptance runs: `absoluteTargets: 0` in every `signalRouting.targets`.
- **Promotion association lost in `repo` mode — closed.** `scopeMode` conflated the repo
  *routing mode* with a *repository-wide* specialist, so Semgrep findings in repo mode
  lost their promotion attribution. The two are now distinct.
- **`rebaseTargets` corrupted relative targets — closed.** It resolved a relative target
  against the process working directory, producing a path belonging to no execution.
  Relative targets are now carried over untouched.
- **Executed specialists were indistinguishable from unscheduled ones — closed.**
  `envelope()` dropped the `job` record, so `specialist-jobs.json` carried no job id,
  state or duration for any tool that actually ran. The job record is now carried through
  and an explicit `outcome` of `AVAILABLE`, `UNAVAILABLE`, `FAILED` or `TIMEOUT` is
  recorded per tool.
- **SIGINT lost the execution — closed.** There was no interrupt handler: Ctrl+C killed
  the process with no expediente update, no stage record, and a managed checkout left on
  disk. `workflow/cancellation.js` records `CANCELLED`, cancels running specialists through
  the scheduler, removes the worktree and re-raises.
- **A symlinked artifact could satisfy the manifest — closed.** `manifest()` never records
  a link, so one substituted afterwards was only checked by content hash. Verification now
  refuses a symlinked artifact outright.
- **Empty routing target was treated as the repository root.** Found by the test written
  for the fix above; a blank entry would have silently widened a scan to every file. It is
  rejected as empty.

## 6. P0-29 verification matrix

Automated coverage is 66 tests across four files. The remaining cases were verified by
real execution, or are still open. This table does not claim coverage that does not exist.

| Area | Verification | Status |
|---|---|---|
| Raw output retained before normalization | unit test + raw artifacts on disk | covered |
| Cloud engine failure becomes incomplete, not empty | unit test | covered |
| Routing modes `file`/`directory`/`repo` | real Semgrep over a real git repo, all three modes | covered |
| Directory and repository-root targets reach the tool | real end-to-end test, findings non-empty | covered |
| Routing targets are relative, not absolute | unit test + 5 real runs, `absoluteTargets: 0` | covered |
| Promotion identity stable across plan rebuilds | unit test | covered |
| Unknown coverage never yields a clean claim | unit test + 5 real runs, all `canClaimClean:false` | covered |
| External actions forbidden by default policy | unit test | covered |
| Cleanup removes only the run-local database | unit test + 5 real runs, all `CLEAN` | covered |
| Candidate carries full correlation id chain | unit test | covered |
| Non-production findings retained, not deleted | unit test + 11-132 observations per run | covered |
| Specialist failure cannot erase a separate finding | real scheduler test, throwing sibling | covered |
| Four distinct specialist outcomes | real processes: missing binary, timeout, non-zero exit, success | covered |
| Executed tool is distinguishable from unscheduled | real end-to-end test, job id and state recorded | covered |
| Semgrep rule identity is path independent | unit test | covered |
| Remote rulesets never selected | unit test | covered |
| Findings confined to the audited repository | unit test | covered |
| SARIF parsing keeps every rule and location | unit test | covered |
| Unusable scan targets rejected before scanning | unit test + real ENOENT reproduction | covered |
| Version probe survives a noisy non-zero exit | unit test | covered |
| Rule precision (no false positives) | unit test + 17 FPs eliminated, 1 TP retained | covered |
| Retry preserves untouched tool evidence | real retry on express | covered |
| Retry reproduces original findings | real retry on express, 16 = 16 | covered |
| Retry keeps raw evidence and attempt history | real retry on swr | covered |
| Relative targets survive a retry into a new worktree | unit test | covered |
| OSV exit-code semantics | unit test + real svelte/flags/swr scans | covered |
| Failure reason is not progress noise | unit test | covered |
| Lockfile presence is detected regardless of file size | unit test with a >512 KB fixture + real flags re-run | covered |
| Probe timeout and retry under load | real runs: 2 Semgrep probe timeouts recovered | covered by execution |
| Heavy/light scheduler limits | real scheduler test, peak concurrency asserted | covered |
| One failing job does not remove its siblings | real scheduler test, throwing and rejecting jobs | covered |
| `core.longpaths` and short attempt ids | real retry in a 124-character output path | covered |
| Idempotency of a full re-run | same commit re-run, stable counts | covered by execution |
| Manifest tamper detection | real manifest: modified bytes, deleted file, absent manifest, substituted symlink | covered |
| Symlink and junction traversal | real junction and file link created, refused by `realContained` | covered |
| Cancellation mid-run (SIGINT) | real interrupt: `CANCELLED` recorded, stage rewritten, worktree removed | covered |
| Disk failure mid-write | real unwritable destination, write reported as failed | covered |
| Network failure mid-scan | real unreachable endpoint, reported as failure | covered |
| Two concurrent runs sharing an execution directory | scheduler isolation test; not a shared execution directory | partial |
| Secret redaction in logs and reports | inspection only | partial |
| CLI flag matrix (every flag, every value) | `--help` plus the flags used above | partial |
| Guard-loaded path: specialists must be `UNAVAILABLE` | not exercised | open |

Three items remain partial or open. They are recorded rather than claimed.


## 7. P0-30 self-audit

Stated plainly, including the parts that are unflattering.

- **False clean.** Not reachable. `canClaimClean` is false in all five runs and unit
  tests cover the invariant. Defects 4, 9 and 12 were all ways of approaching a silent
  false clean, and all three were found and closed.
- **Fail-open behaviour.** Three of the sixteen defects made the product report a
  healthier state than reality: Semgrep returning zero findings because its ruleset
  could not load, the version probe marking a working tool unavailable, and SCA declaring
  itself not applicable on the largest lockfile. The last one is the most serious defect
  in this document, because it hid 25 real vulnerabilities behind a reassuring
  `notApplicable` label. All three are closed and now have regression tests.
- **SCA coverage.** 111 known vulnerabilities across the three repositories that have a
  lockfile are reported as findings rather than resolved. That is the correct v1
  behaviour for a read-only audit tool, but it means the tool surfaces dependency risk
  without triaging it.
- **Evidence loss on retry.** Defects 11, 12 and 13 were three separate evidence-loss
  paths in the retry code. All are closed and verified against real retries.
- **Honest status reporting.** Defect 15 published 86 real vulnerabilities under an
  unexplained `ERROR`. Fixed. Every non-`COMPLETE` envelope now carries a reason.
- **Unreviewed tool output.** Semgrep and OSV JSON are parsed defensively, and a
  parseable payload is still not trusted to mean the scan succeeded; the exit status and
  the parsed result are considered separately. This is why defect 15 was possible at all
  and is now covered by tests.
- **Debug residue.** Three throwaway scripts (`sg-probe.js`, `line-check.js` and a
  scratch probe used to inspect the specialist stage) were written during this work and
  have been deleted. `scripts/adapter-smoke.js`, `scripts/acceptance-summary.js` and
  `scripts/candidate-why.js` are kept because they are reusable and are referenced from
  this document.
- **Working tree.** All changes are unstaged and uncommitted, as required. Nothing was
  pushed.
- **Untouched surfaces.** Sentinel Cloud, Purple, Oracle and the five target repositories
  were not modified. Semgrep rules are vendored and local; remote rulesets are disabled
  by configuration and by test.
- **Known gap carried forward.** The guard-loaded host path is still unexercised: no run
  has been made under `runtime-guard.js` to confirm specialists resolve as `UNAVAILABLE`
  rather than executing. Every other item from the P0 list is closed.

## 8. P0 closure checklist

| # | Requirement | How it was satisfied | Status |
|---|---|---|---|
| P0-1 | Real `file`/`directory`/`repo` routing through specialist, normalization, correlation and report | `test/routing-e2e.test.js` drives the real Semgrep binary over a real git repository in all three modes; findings must be non-empty, attributed to a promotion, and must survive `correlate()` and `auditVerdict()` | closed |
| P0-2 | Routing targets relative, not absolute | `workflow/paths.js` owns the contract; `absoluteTargets: 0` across all five acceptance runs | closed |
| P0-3 | Real tests for tamper, links, SIGINT, disk, network and concurrency | `test/resilience.test.js`, 20 tests, no mocks | closed |
| P0-4 | Full regression green | `npm test` 66/66, zero skipped | closed |
| P0-5 | Five pinned repositories re-run | `p0-final` re-run reproduced every baseline count except the two live-database OSV counts | closed |
| P0-6 | Explicit `AVAILABLE`/`UNAVAILABLE`/`FAILED`/`TIMEOUT` with continuity | `OUTCOME` and `specialistOutcome()` in `workflow/specialist-runtime.js`; `test/outcomes.test.js` produces all four from real processes | closed |
| P0-7 | Self-audit | Section 7. No TODO/FIXME, no `shell: true`, no `exec`, no hardcoded secret, no silent catch outside the PATH probe, containment hardened and symlink refusal added | closed |
| P0-8 | Documentation | This document, with the baseline and the closure run both recorded | closed |
| P0-9 | Done only when every criterion passes | This table; the one unexercised path is named above rather than glossed | closed |

## 9. Reproduction

```
npm test

node audit-runner.js preflight --repo <path> --commit <40-sha> --json
node audit-runner.js run --repo <path> --commit <40-sha> --output <dir>
node audit-runner.js retry <executionDir> --only semgrep
node audit-runner.js cleanup <executionDir>
node scripts/acceptance-summary.js <base-dir>
```

Acceptance evidence for the baseline is under `%TEMP%\sa\final\` and for the P0 closure
re-run under `%TEMP%\sa\p0-final\`, one directory per repository, each containing a
disposable worktree removed after the run, the raw and normalized specialist output, the
job ledger, the stage state and the expediente.
