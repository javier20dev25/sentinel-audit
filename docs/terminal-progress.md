# Terminal progress map

Sentinel Audit renders live progress for `run` and `scan` on stderr. It uses
events emitted by the pipeline, so it shows states rather than guessed progress
percentages.

## Stages

| Stage | What the analyst sees |
|---|---|
| Preflight | Repository and tool readiness checks |
| Identity | Immutable commit and managed checkout |
| Engine | Local Sentinel worker or hosted Sentinel Cloud |
| Routing | Signal decision and selected file/target counts |
| Specialists | Per-tool queue, running, and terminal state |
| Correlation | Evidence correlation completion or failure |
| Triage | Candidate verdict and triage decision count |
| Cleanup | Managed checkout cleanup state |

`COMPLETE` means that stage returned successfully; it is not a claim that the
repository is vulnerability-free. `INCOMPLETE`, `FAILED`, `NOT_RUN`, and
`PLANNED` remain visible so a skipped or degraded analysis cannot look complete.
Specialist duration is reported only after the scheduler records it.

## Terminal behavior

The map redraws in place and uses ANSI color only when stderr is a TTY, `NO_COLOR`
is absent, and `TERM` is not `dumb`. In pipes and CI it prints readable plain
text. `--json` and `--quiet` suppress it. JSON output stays on stdout; progress
stays on stderr.

Example final view:

```text
Sentinel Audit | mapa de ejecución
  [OK] Preflight del repositorio: COMPLETE — READY
  [OK] Commit fijado y checkout aislado: COMPLETE — commit 3f8a21c4d019
  [OK] Motor Sentinel: COMPLETE — local; estado COMPLETE; 4 señales normalizadas
  [OK] Enrutamiento de señales: COMPLETE — 3 destinos; 12 archivos
  [OK] Analizadores especialistas: COMPLETE — 2 trabajos registrados
      [OK] semgrep: COMPLETE — 811 ms
      [TIMEOUT] codeql: TIMEOUT — 300000 ms
  [OK] Correlación de evidencias: COMPLETE — 2 candidatos
  [OK] Triage de candidatos: COMPLETE — REVIEW_REQUIRED; 2 decisiones de triage
  [OK] Limpieza del checkout: COMPLETE — CLEAN
```

Hosted engine integrations currently return an aggregate result, not events from
their internal analyzer stages. The map names the provider and reports the
aggregate status and signal count without inventing internal tools or timing.

## Evidence

The map is an operator view, not the audit record. The execution directory
contains `state/stages.json`, `specialist-jobs.json`, raw and normalized tool
artifacts, correlation records, the report, and the manifest used to verify
artifact integrity. Use those files for post-run review and reproducibility.
