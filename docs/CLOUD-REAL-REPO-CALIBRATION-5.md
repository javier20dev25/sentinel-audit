# Cloud real-repo calibration: 5 repositories

Local date: 2026-09-27
Revision: **2** — P0-A fixed in Sentinel Cloud, all five re-measured.
Status: **the 50+ campaign still did not run.** See the gate.

## Question

The first campaign batches were produced by the archived Purple engine
(`sentinel-purple` `commensal`). None of that evidence exercised the Sentinel
Cloud sensor. This re-measures the same five repositories, at the same commits,
through the Sentinel Cloud worker engine, and asks what the engine yields and
whether the funnel is worth its cost.

## Why this is revision 2

Revision 1 measured 3 of 5. The engine threw
`TypeError: alert.line.substring is not a function` on svelte and flags and
aborted both scans entirely. Those two repositories contributed zero signals and
zero candidates, and the run was gated FAIL. The defect was then fixed in
Sentinel Cloud and the whole set re-measured. Both revisions are reported here
because the difference between them is the finding: a 40% sample loss did not
look like a precision problem, it looked like a scanner that was merely
inconsistent.

## Identity

| Role | Identity |
|---|---|
| Runner | `9e747a1f447a2b513d004ccb802ec3cc51ed738d` |
| Engine commit | `f674ffafefee6923aa91a4bced43d1810d74ff2c` |
| Engine worktree during measurement | clean |
| Engine scanner SHA-256 | `3b9b653d4916cd85c5869a0dae14594c645a7239916df715f600100d466f6c6e` |
| Engine invocation | `scanDirectory(root, null, 5, { mode: 'local', profile: 'DEFAULT' })` |
| Historical engine | `engine@78c1fe262809b02fbbe4eec83312039ca113b815` (Purple, archived) |
| Production parity | **UNKNOWN** |
| Engine coverage | **ENGINE_COVERAGE_UNMEASURED** |

All five repositories ran at the **same commit** as the historical Purple run, so
the comparison is like-for-like. Every record carries the same engine head, the
same scanner hash, and `filesScanFailed 0 / alertsEnrichFailed 0 /
degradationSamples 0`.

## Results

| Repo | Commit | Purple signals | Purple cands | Cloud status | Cloud signals | Cloud actionable | CodeQL | Semgrep | Cloud cands | Observations |
|---|---|---|---|---|---|---|---|---|---|---|
| expressjs/express | `9a34acf` | 101 | 0 | PARTIAL | 152 | 129 | 5 | 2 | **0** | 13 |
| fastify/fastify | `bc25b74` | 296 | 0 | PARTIAL | 275 | 238 | 0 | 0 | **0** | 59 |
| sveltejs/svelte | `f908535` | 1788 | 14 | PARTIAL | 292 | 231 | 22 | 2 | 15 | 148 |
| vercel/flags | `c3026fe` | 114 | 0 | PARTIAL | 435 | 144 | 5 | 1 | 2 | 192 |
| vercel/swr | `9ed1240` | 19 | 1 | PARTIAL | 139 | 117 | 7 | 1 | 1 | 16 |
| **total** | | **2318** | **15** | | **1293** | **859** | **39** | **6** | **18** | **428** |

5 of 5 complete. Candidate yield per signal: Cloud 1.39%, Purple 0.65%.

## P0-A: fixed, and it was an availability defect, not a precision one

`packages/worker/core/scanner/index.js:101` called `alert.line.substring(0, 100)`
behind a bare truthiness check. Line 98 of the same function filters
`typeof e === 'string'`; line 100 checked nothing. A numeric `line` is an
expected shape in this codebase, not an impossible one — `p0_gated_policy.js:30-33`
documents `line: number` in its own contract, `forensics.js:37` assigns
`line: lineNumber`, and `evidence_graph.js:315` returns a computed line count.

The call chain was `scanDirectory` per-file loop → `enrichAlert:132` →
`deriveSignals:101`, run for **every** alert with no per-alert `try/catch`, so
one alert carrying a number rejected the whole `scanDirectory` promise. There
was no partial result: the caller got nothing for the whole repository.

Fixed by a `typeof` guard, so a non-string `line` now falls through to the
script and evidence branches and can honestly return `[]`. A non-string `line` is
location data, not evidence, and coercing it would have put a bare line number
into an evidence field. The per-file loop additionally catches per file and per
alert and counts what it dropped, so a degraded scan is visible rather than
silently smaller.

**The type guard is what resolved it.** All five repositories report
`alertsEnrichFailed 0` and `degradationSamples 0`, so nothing was swallowed by
the catch. Well-formed alerts take the identical string path, including the
empty-string skip.

Behaviour check: `b6_b_embedded_binary` and `detection_gaps` give 24 passed /
1 failed both before and after the change. The single failure is a pre-existing
`B6_B` rationale assertion, verified by stashing the change and re-running; it
is not a regression.

## P0-B: fixed in the runner, and it was the more dangerous one

`buildRoutePlan` only received `findings`, so an engine that returned nothing
because it threw was indistinguishable from an engine that found nothing. Both
were recorded as

```
decision: NO_ACTIONABLE_SENTINEL_FINDINGS
reason:   Etapa A emitted no actionable Sentinel Cloud signal
```

That sentence asserts the engine ran and had nothing to say. It is false when
the engine threw, and it is the shape of a false clean claim.

`buildRoutePlan` now takes the Sentinel tool status, reports
`SENTINEL_ENGINE_INCOMPLETE` with `engineIncomplete: true` and a reason stating
that absence of findings is not evidence of absence, and routes no secondary
tool. A successful zero-signal scan is unchanged and still reports
`NO_ACTIONABLE_SENTINEL_FINDINGS`, which the verdict layer already refuses to
treat as a security claim. Five regression checks cover the crashed case.

P0-B is the one that would have survived review. P0-A was loud and self-announcing.
P0-B laundered the loud one into a quiet green line in the record.

## What the funnel yields

| Funnel stage | Count |
|---|---|
| Sentinel Cloud signals | 1293 |
| Classified `ACTIONABLE_SIGNAL` | 859 (66.4%) |
| Repositories that amplified | **5 of 5** |
| Candidates from Sentinel signals | **0** |
| Candidates from secondary tools | 18 (CodeQL 15, Semgrep 3) |
| Observations retained | 428 |

Three things matter here.

**Not one candidate came from a Sentinel signal.** All 18 candidates are
corroborated by a secondary authority: CodeQL 15, Semgrep 3. Sentinel Cloud's
own contribution to the candidate set is zero across all five repositories. Its
role in the funnel is currently to decide *where* to look, and the specialist
tools to decide *what* is there.

**The yield is extremely repo-dependent, not uniformly useful.** svelte alone
contributes 15 of 18 candidates, flags 2, swr 1 — and express and fastify
contribute **zero from 367 actionable signals**. A funnel that returns nothing on
two of five repositories while amplifying 100% of them is not a triage step; on
express and fastify the amplification bought CodeQL and Semgrep runs that
produced nothing either.

**`ACTIONABLE_SIGNAL` at 66.4% is not a routing signal.** It is high enough that
the gate fires on every repository, so "only justify specialists when warranted"
is not true of this configuration.

### A caution on the 18 candidates

They are all `PLAUSIBLE_SECURITY_ISSUE` and **all 18 are unadjudicated**. None is
a confirmed vulnerability. Several concentrate in paths that look like
non-production tooling rather than shipped library code:

- `playgrounds/sandbox/scripts/download.js` — 4 candidates
- `playgrounds/sandbox/scripts/create-app-svelte.js` — 1
- `packages/svelte/scripts/check-treeshakeability.js` — 1

That is 6 of 18 pointing at playground and maintenance scripts. Whether those
belong in a security review of the library is a scoping decision, not something
this calibration settles. It is flagged as the next precision question rather
than asserted as a conclusion.

## Answers to the four questions

**Does Cloud find what Purple found?** Not comparably, and the counts are not
comparable as quality. Cloud is in Purple's range on express (152 vs 101) and
fastify (275 vs 296) and far above it on flags (435 vs 114) and swr (139 vs 19),
while far below on svelte (292 vs 1788). The categories, the actionable
classification and the coverage semantics all differ, and Cloud's coverage is
unmeasured, so a lower count is not a better result. What the set does establish
is that Cloud's signal volume is not uniformly lower than Purple's.

**What is the cost?** express 225 s, fastify 305 s, swr 228 s, flags 252 s,
svelte 505 s for the full funnel including specialists. 859 actionable signals
produced 39 CodeQL and 6 Semgrep findings and 18 candidates.

**Can findings be corroborated?** Yes, at a rate of 18 candidates from 1293
signals, but not by Sentinel itself. Corroboration comes from CodeQL and Semgrep
every time.

**What is the precision calibration direction?** Three concrete items, in
priority order.

1. **Scoping.** Decide whether playground and maintenance scripts are in scope.
   That single decision moves 6 of 18 candidates out of the set, and it should
   be made before any threshold is tuned.
2. **The actionable threshold.** At 66.4% it routes on every repository. It needs
   to require corroboration-relevant evidence, not bucket membership, or the
   amplification cost stays unconditional.
3. **The express/fastify null result.** 367 actionable signals and zero
   candidates in two repositories. Either the actionable classification there is
   mostly noise, or the specialists are missing real issues. That distinction
   should be settled on those two repositories before scaling, not after.

## Gate

**HOLD. The 50+ campaign did not run, and this result is not a reason to start it
yet.**

The P0-A blocker is cleared: 5 of 5 complete, engine committed, no degradation
counted, all five at the same commit as the historical baseline. That was the
gate for *measuring*.

It is not a gate for *scaling*, for two reasons visible in the numbers above.
First, 0 of 18 candidates originate from Sentinel Cloud, so at present the
engine adds amplification cost without adding candidates. Second, the yield is
carried by one repository and the two most conventional Node libraries in the set
return nothing at all from hundreds of actionable signals. Scaling now would
produce a large sample whose aggregate yield is dominated by whatever kind of
repository happens to be in it.

Recommended order: adjudicate the 18 candidates, settle the playground scoping
question, investigate the express/fastify null result, then re-measure. All four
are cheaper than a 50+ run.

## Not claimed

- Not production parity with the deployed worker. `PRODUCTION_PARITY_UNKNOWN`.
- Not measured engine coverage. The scanner exposes no parsed-file or
  parser-error counters.
- Not a clean result anywhere.
- Not a security assessment of any of the five repositories. No candidate is
  confirmed and none has been adjudicated.
- The 47 remaining historical repositories were not touched.

## Commits

| Repo | Commit | Contents |
|---|---|---|
| `sentinel-audit` | `1130a84` | Cloud-first engine invocation replacing Purple |
| `sentinel-audit` | `9e747a1` | P0-B routing honesty fix + 5 regression checks |
| `sentinel-cloud` | `f674ffaf` | P0-A `deriveSignals` type guard + per-alert containment |
| `sentinel-audit` | `bda5e6b` | this report, revision 1 |

No push, no PR, no disclosure. The 641 untracked files in the `sentinel-cloud`
working tree were not staged and remain untracked.

## Artifacts

- `cloud-calibration-5/identity.json` — identity record, both engines, five
  pinned commits and tree hashes
- `cloud-calibration-5/comparison.json` — machine-readable Purple vs Cloud
- `cloud-calibration-5/compare.js` — the aggregator
- `cloud-calibration-5/out/<repo>/` — `expediente.json`, raw `sentinel.json`
  (engine output preserved before normalization), `REPORT.md`, `codeql.sarif`,
  `trivy.json`
- Historical Purple results remain untouched in `supply-chain/results/`
