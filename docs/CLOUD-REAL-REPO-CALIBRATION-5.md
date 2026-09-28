# Cloud real-repo calibration: 5 repositories

Local date: 2026-09-27
Status: **STOPPED after the controlled 5. The 50+ campaign did not run.**

## Question

The first campaign batches were produced by the archived Purple engine
(`sentinel-purple` `commensal`). None of that evidence exercised the Sentinel
Cloud sensor. This re-measures the same five repositories, at the same commits,
through the Sentinel Cloud worker engine, and asks what the engine actually
yields and whether the funnel is worth its cost.

## Identity

| Role | Identity |
|---|---|
| Runner, measurement | `1130a84b1694803da1d6c5b43c7192411477a7ff` |
| Runner, final | `9e747a1f447a2b513d004ccb802ec3cc51ed738d` (routing honesty fix, below) |
| Engine source | `sentinel-cloud` @ `e9e3036026b12862e91f0fb48ad3a482787e8507` |
| Engine scanner SHA-256 | `a88a67b73347a53409f8a0fbd241b8009223a181dd0f66d27ec17a5e50ca39d2` |
| Engine invocation | `scanDirectory(root, null, 5, { mode: 'local', profile: 'DEFAULT' })` |
| Historical engine | `engine@78c1fe262809b02fbbe4eec83312039ca113b815` (Purple, archived) |
| Production parity | **UNKNOWN** |
| Engine coverage | **ENGINE_COVERAGE_UNMEASURED** |

The engine checkout carries 641 untracked files, all under `docs/`, `scratch/`,
`.c7-sandbox/` and `src/` tests. Nothing under `packages/worker` is modified or
untracked, and the scanner, `ast_inspector` and worker config hashes match the
gate document, so the measured engine is the committed one. The scanner's
71-module require graph was checked: it references no `sentinel-cloud` `src/`
file. The only `src/` occurrences in the scanner are an HTML `<script src=>`
regex at line 497 and a comment at line 1447.

All five repos ran at the **same commit** as the historical Purple run, so the
comparison is like-for-like. No push, no PR, no disclosure. Sentinel Cloud and
Purple are both unmodified.

## Results

| Repo | Commit | Purple signals | Cloud status | Cloud signals | Cloud actionable | CodeQL | Semgrep | Candidates | Observations |
|---|---|---|---|---|---|---|---|---|---|
| expressjs/express | `9a34acf` | 101 | PARTIAL | 152 | 129 | 5 | 2 | 0 | 13 |
| fastify/fastify | `bc25b74` | 296 | PARTIAL | 275 | 238 | 0 | 0 | 0 | 59 |
| vercel/swr | `9ed1240` | 19 | PARTIAL | 139 | 117 | 7 | 1 | 1 | 16 |
| sveltejs/svelte | `f908535` | 1788 | **ERROR** | 0 | - | 0 | 0 | 0 | 0 |
| vercel/flags | `c3026fe` | 114 | **ERROR** | 0 | - | 0 | 0 | 0 | 0 |

Three of five repositories completed. Two produced no Sentinel signal set at
all, because the engine threw.

## P0-A: the engine aborts the entire repository scan on one malformed alert

`packages/worker/core/scanner/index.js:101`

```js
if (alert.line) {                            // truthiness only, no type guard
    return [alert.line.substring(0, 100)];   // TypeError if line is truthy and not a string
}
```

The call chain is `scanDirectory` per-file loop (lines 1294-1306) ->
`enrichAlert` (line 132) -> `deriveSignals` (line 101). `enrichAlert` runs for
**every** alert and the loop has no per-alert `try/catch`, so a single alert
carrying a non-string `line` rejects the whole `scanDirectory` promise and the
caller receives nothing for the entire repository. There is no partial result.

Line 98 of the same function filters `typeof e === 'string'`. Line 100 does not
check the type at all, so the function violates its own standard two lines
later. The codebase already documents `line` as a number in
`p0_gated_policy.js:30-33`, and `forensics.js:37` and `evidence_graph.js:315`
assign numeric line values, so a numeric `line` is an expected shape, not an
impossible one.

Reproduced on 2 of 5 pinned real repositories. The exact emitting detector was
not isolated; the defect site and the blast radius are. The fix is a type guard
at the defect, independent of which detector emits the shape.

**Sentinel Cloud was left unmodified.** This is reported, not patched.

## P0-B: the routing layer reported the crash as "no actionable findings"

The first pass recorded both failures as:

```
decision: NO_ACTIONABLE_SENTINEL_FINDINGS
reason:   Etapa A emitted no actionable Sentinel Cloud signal
```

`buildRoutePlan` only received `findings`, so an engine that returned nothing
because it threw was indistinguishable from an engine that found nothing. The
sentence asserts the engine ran and had nothing to say, which is false. It is
the shape of a false clean claim: a reader taking the routing line at face value
would conclude "Etapa A found nothing actionable" from a run where Etapa A never
returned.

Fixed in `9e747a1`. `buildRoutePlan` now takes the Sentinel tool status and
reports `SENTINEL_ENGINE_INCOMPLETE` with `engineIncomplete: true`, a reason
stating that absence of findings is not evidence of absence, and no secondary
tool routing, because a scan that did not complete justifies nothing. It never
reports `AMPLIFY` on an incomplete Etapa A. A successful zero-signal scan is
unchanged and still reports `NO_ACTIONABLE_SENTINEL_FINDINGS`, which the verdict
layer already refuses to treat as a security claim. Both repos were re-run and
now record the honest state.

## What the funnel yields

Of 566 Sentinel Cloud signals across the three completed repositories, 484 were
classified `ACTIONABLE_SIGNAL` and every one of the three amplified to
specialists. **Not one Sentinel signal survived corroboration into a
candidate.** The single candidate in the set is Semgrep's, at
`scripts/bump-next-version.js:19` in swr, disposition `PLAUSIBLE_SECURITY_ISSUE`,
pending human adjudication.

| Funnel stage | Count |
|---|---|
| Sentinel Cloud signals | 566 |
| Classified actionable | 484 (85.5%) |
| Repositories that amplified | 3 of 3 completed |
| Candidates from Sentinel signals | **0** |
| Candidates from secondary tools | 1 |
| Observations retained | 88 |

Three consequences.

1. `ACTIONABLE_SIGNAL` is not discriminating at 85.5%. It routes specialists on
   essentially every repository, so the routing gate is effectively always-on and
   "only justify specialists when warranted" is not currently true.
2. `AMPLIFY` fired on 3 of 3. With no repository where Sentinel stayed quiet, the
   threshold's behavior on a quiet repository is untested by this sample.
3. Candidate yield per signal is 0.18% for Cloud against 0.65% for Purple on the
   same commits, and every Cloud candidate came from a secondary tool rather than
   from Sentinel. On this sample the engine's own contribution to the candidate
   set is zero.

This is a precision problem, not a recall problem. The engine is not quiet; it is
loud, and the noise does not currently convert.

## Answers to the four questions

**Does Cloud find what Purple found?** Unanswerable for 2 of 5, and the reason is
a crash, not a clean result. For the three that completed, Cloud is in the same
range as Purple on express (152 vs 101) and fastify (275 vs 296) and far above
it on swr (139 vs 19). Signal counts are not comparable as quality: the
categories, coverage and actionable classification all differ, and Cloud's
coverage is unmeasured.

**What is the cost?** Express 257 s, fastify 295 s, swr 251 s for the full funnel.
Svelte and flags cost 41 s and 35 s because they crashed almost immediately, so
their cost figures are meaningless. 484 actionable signals produced 12 CodeQL
and 3 Semgrep findings and 1 candidate.

**Can findings be corroborated?** One of five repositories produced a
corroborated candidate, and it came from Semgrep, not Sentinel. On this sample
Sentinel Cloud's own signals corroborated at a rate of zero.

**What is the precision calibration direction?** The actionable threshold is too
loose to route on, and the actionable-to-candidate conversion is the real gap.
Before any 50+ run, either the `ACTIONABLE_SIGNAL` classification needs to
require corroboration-relevant evidence, or the engine needs to rank rather than
bucket. A funnel that amplifies 100% of scanned repositories is a cost centre,
not a triage step.

## Gate

**FAIL, do not proceed to the 50+ campaign.**

Not because precision is poor, though it is, but because a scanner that loses
40% of a small real sample to an unhandled input shape cannot be used to
calibrate anything. Until P0-A is fixed, every number in a larger run is
uninterpretable: an engine crash is indistinguishable from a quiet repository
unless each record is inspected by hand, and that is not a property a campaign
can rely on.

## Not claimed

- Not production parity with the deployed worker. `PRODUCTION_PARITY_UNKNOWN`.
- Not measured engine coverage. The scanner exposes no parsed-file or
  parser-error counters.
- Not a clean result anywhere. Zero signals from a crashed engine are not zero
  risk.
- Not a security assessment of any of the five repositories.
- The 47 remaining historical repositories were not touched.

## Next step, and the one that must come first

Fix P0-A in Sentinel Cloud: a type guard at `index.js:100-101`, plus a
per-alert `try/catch` in the `scanDirectory` loop so a single malformed alert
degrades one alert instead of the whole repository. Then re-run these five and
confirm 5 of 5 complete before considering a larger sample.

## Artifacts

- `cloud-calibration-5/identity.json` — full identity record, both runner
  commits, engine hashes, pinned commits and tree hashes
- `cloud-calibration-5/comparison.json` — machine-readable Purple vs Cloud
- `cloud-calibration-5/compare.js` — the aggregator
- `cloud-calibration-5/out/<repo>/` — `expediente.json`, `sentinel.json`,
  `REPORT.md`, `codeql.sarif`, `trivy.json`
- Historical Purple results remain untouched in `supply-chain/results/`
