# Changelog

All notable changes to the audit runner. Every entry is a freeze tag; nothing
in this repository is released without one.

## v1.2 — `audit-runner-v1.2-freeze` (`16b1dab`)

Fixed: the disclosure channel could name the wrong destination.

`fastify/fastify` was reported as
`DISCLOSURE_READY  security@lists.openjsf.org`. That address is the OpenJS CNA
**secondary contact** (`SECURITY.md:167`). Fastify's actual channel is a private
GitHub Security Advisory (`SECURITY.md:66`), and the same policy states the
project does not support reporting outside that process (`SECURITY.md:106`).
The expediente pointed a disclosure at the one destination the policy excludes.

Two causes:

1. Vetting signals were bare substring matches, so
   *"Fastify's HackerOne program is closed"* (`SECURITY.md:74`) scored as a
   live, vetted HackerOne channel.
2. Only email addresses were extracted. The primary channel is a URL, so the
   real route was invisible and the CNA fallback was all that remained.

Changes:

- Keywords are judged per sentence, so a channel retired in one section cannot
  mark a live channel in another as vetted. Retired channels are reported
  separately as `retiredChannels`.
- Private report endpoints (`security/advisories[/new]`) are extracted as
  `channels`; a policy naming one is vetted on that basis alone.
- Contacts are attributed to their nearest preceding markdown heading, so a
  "Secondary Contact" address is reported as fallback and is not by itself
  grounds for calling a policy vetted.

Verified on all four targets carrying a policy, no regressions: `fastify`
(channel = GitHub advisories URL, fallback = OpenJS CNA, retired = HackerOne),
`nest` (`support@nestjs.com`, unchanged), `next.js` and `rpcenum` (no channel,
unchanged). Determinism re-checked on `fastify`: two runs byte-identical.

## v1.1 — `audit-runner-v1.1-freeze` (`ab60f15`)

Fixed: a skipped tool was reported as a clean run.

`fastify/fastify` returned `CLEAN_WITH_FULL_COVERAGE` with
`canClaimClean: true` while OSV had skipped itself, noting *"SCA impossible,
which is a COVERAGE GAP and not a clean result."* Seven tools were applicable
and one never ran.

`auditVerdict` built `degraded` from `PARTIAL`/`ERROR`/`UNSUPPORTED` only, so
`SKIPPED` fell through every gate. It was not degraded, not hard-failed, not
limited, and was excluded from `required`, whose count (6) was the only place
the skip was visible.

Changes:

- `SKIPPED` is a hard coverage failure: `analysisState` and verdict become
  `PARTIAL_ANALYSIS`, `canClaimClean` becomes `false`.
- `skippedTools` is reported with each tool's reason.
- `NOT_APPLICABLE` stays excluded. Bandit on a JavaScript repo is not a gap;
  OSV without a lockfile is. Both branches are now exercised by real targets.

Re-verified: `fastify` reports 1 of 7 applicable tools not completing, with the
reason surfaced. `nestjs/nest` shows no regression, no skips,
`CANDIDATES_FOUND` then `CLEAN_WITH_FULL_COVERAGE` after adjudicating
`SAR-0001`. Determinism holds.

## v1 — `audit-runner-v1-freeze` (`3819cc0`)

Initial freeze. **Known wrong in two ways**, described in v1.1 and v1.2 above.
Retained deliberately: a freeze that gets quietly rewritten is worse than one
that keeps its mistakes visible, because the mistakes are the argument for the
invariants.

Frozen invariants at v1:

- `SENTINEL_SIGNAL != CANDIDATE != CONFIRMED_ISSUE`; only a human adjudicates.
- A finding count is never reported without coverage.
- Git is the source of truth for `SECURITY.md`, `LICENSE`, commit and tree.
- Every candidate preserves its full evidence chain.
- Publication is unconditionally forbidden.
- Target code is never executed, built, tested or installed.
- The runner orchestrates; it does not re-implement detection.

Verified on `nestjs/nest` at `b58554ea5857`: two consecutive runs produced
byte-identical evidence after removing timestamps, paths and wall-clock.
