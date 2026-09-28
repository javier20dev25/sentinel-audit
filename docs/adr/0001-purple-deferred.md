# ADR-0001: Purple attack-path engine deferred in favor of external analyzers

- **Status:** accepted
- **Date:** 2026-09-27
- **Freeze:** `sentinel-purple` stays at `78c1fe2`, tags `p1.3-freeze`, `p1.4-freeze`
- **Affects:** the audit pipeline's tool roster and the ROI of a second engine

## Context

Purple was built to produce attack-path hypotheses: given behavior Sentinel
flagged, propose a route from an attacker-controlled source to a sensitive
sink. It is a real capability and a reasonable thing to want.

Measured against the pipeline, it does not pay for itself.

Across audited targets Purple produced 21 to 27 signals, none of which were
`ENTAILED`, and **zero** that survived correlation into a candidate. The only
candidate the campaign produced came from Semgrep, on `nestjs/nest`; CodeQL
produced findings that correlation correctly scoped out of production rather
than promoting. Purple never promoted a single signal on its own, and the
layers that would have consumed its output were the ones a human had to
adjudicate anyway.

So the cost was real and recurring: a tool in the critical path, wall-clock
budget, tokens, and a large volume of output requiring manual review, in
exchange for zero confirmed or plausible findings.

The negative result is worth stating precisely, because it is more useful
than a vague "it did not work":

1. The attack-path hypothesis is sound and worth keeping as a research goal.
2. Implementing it well is expensive.
3. The current model emits weak signals: it flags categories, not reachability.
4. Existing tools already answer the hard parts of the question better.
   CodeQL resolves dataflow Purple cannot; Semgrep supplies pattern semantics.
5. Maintaining a second engine alongside those tools does not justify its
   marginal contribution at this stage.

The prior is not a reason to keep it. Money already spent does not earn future
maintenance.

## Decision

Purple is **frozen and archived as an experimental prototype**. It is removed
from the critical audit path.

```
normal audit:
  Sentinel (discovery)  +  CodeQL / Semgrep / Bandit / Trivy / OSV (verification)
  no Purple
```

Purple is not deleted. It stays at `78c1fe2` with its freeze tags intact and
remains runnable. It is simply no longer something a routine audit pays for.

## Consequences

**Gained.** One fewer engine in the critical path, less wall clock and token
spend per audit, and a shorter path from signal to evidence. The audit's
defensible claim gets stronger, because CodeQL and Semgrep carry
reachability claims that are checkable by a third party.

**Lost.** The one thing Sentinel and the specialized tools do not provide is a
proposal for *how* untrusted input reaches a sink. The chain still works
without it:

```
Sentinel:      there is an eval here
Semgrep:       this is an unsafe-eval pattern
CodeQL:        the argument originates at <source>
analyst:       that source is attacker-controlled
```

That chain reaches the same conclusion without a hypothesis engine in the
middle, and every step in it is independently reproducible.

**Risk accepted.** A category of finding that only Purple's model could have
surfaced may now go unnoticed. Judged against zero promoted findings across the
campaign, that risk is smaller than the operational cost of keeping it.

## What would reverse this

Revisit if Purple reaches a measurable bar:

- `ENTAILED` rate above zero on targets with known reachable flows, and
- at least one candidate promoted to `PLAUSIBLE_SECURITY_ISSUE` or better that
  no other tool in the roster produced, and
- a wall-clock cost that does not dominate the audit budget.

Reaching the bar is a reason to unfreeze, not a reason to assume it.

## Note on scope

This ADR originally changed the pipeline's roster without changing its code:
`adapters/index.js` still had a Purple adapter, and excluding Purple meant
`--skip-specialists`, which records a tool as `SKIPPED`. That is a coverage
failure, so deliberately leaving Purple out was indistinguishable from a tool
that broke, and it would have forced `PARTIAL_ANALYSIS` on every target.

As of `v1.5` the gap is closed on the runner side. `--skip-purple` records
Purple as `NOT_APPLICABLE`, which keeps it out of `required` and `degraded` in
`auditVerdict` and states the decision in the expediente. A genuinely skipped
tool still degrades; that distinction is asserted in
`tools/verdict-matrix.js` rather than left to convention.

`adapters/index.js` still contains the Purple adapter and it remains runnable.
The exclusion is opt-in and recorded, not silent. Sentinel and Purple are
unmodified by this change.

## Superseding implementation note (2026-09-27)

The v1.5 implementation note above is historical and no longer describes the
active runner. The campaign runner was rewired to call the local Sentinel Cloud
worker scanner directly. Purple has no active config entry, is not exported by
the shipping adapter module, and is absent from the audit tool roster and
routing. The legacy paragraphs above document the prior freeze state only; do
not use them as current execution instructions. See
`docs/SENTINEL-CLOUD-FIRST-ARCHITECTURE.md` and
`docs/SENTINEL-CLOUD-DIRECT-GATE.md` for the current architecture and gate.
