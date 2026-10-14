# ARTIFACT_HASHES.md — Phase Y2.3 (Sentinel Y v0.3)

SHA-256 de los artefactos de la fase de aceptación. Registrado para sellado/versionado.

## Motores
| Ruta | Estado | SHA-256 |
| --- | --- | --- |
| `sentinel-y/v0.1/index.js` | Congelado | `175004F5AE9E110929D445B27AC9FF40A6AE0EB7B2C8F04CEBDFD6F520905A28` |
| `sentinel-y/v0.2/index.js` | Congelado | `AC9BECBE913B2114120EF5A33D889A869C25B583252836E7D3C0EEC7597B83C8` |
| `sentinel-y/v0.3/index.js` | Candidato (no sellado) | `93B9534F6C4F51782A00FAD478D553AD545FD6D18314EB3B82FF3134461D1E54` |

## Artefactos de aceptación
| Ruta | SHA-256 |
| --- | --- |
| `benchmark/phase_y2_3/run_phase_y2_3_acceptance.js` | `1A3272D97C05DA47B5C653A79CC0761A8C9C0C25D4428FB401A0CA5723C04C89` |
| `benchmark/phase_y2_3/PHASE_Y2_3_RESULTS.jsonl` | `3ABF92182EE166059DF4968FCB628F387B82C0571CFE896C0FBC062F4658D99B` |
| `benchmark/phase_y2_3/PHASE_Y2_3_METRICS.json` | `0F193A1DFC829F5139089EF8B33973F8C71FE9FDEB52852855CEEC1694626388` |
| `benchmark/phase_y2_3/PHASE_Y2_3_SUMMARY.md` | (regenerar tras edición) |
| `benchmark/phase_y2_3/PHASE_Y2_3_REGRESSION_TESTS.md` | `3AEFBEFF4BB340BC203E873F1F8FE5FA7FDF67BEE8C81840E7436EBF2E4C8B88` |
| `benchmark/phase_y_prospective/ENGINE_SELECTION_RECORD.md` | (regenerar tras edición) |

> Los hashes de `SUMMARY.md` y `ENGINE_SELECTION_RECORD.md` cambian cuando se editan; recalcular con `node -e` al momento del sellado.

## Estado de versionado (Git)
`git status --porcelain` en `sentinel-audit` reporta sin rastrear (untracked): `benchmark/phase5/`, `benchmark/phase_y1/`, `benchmark/phase_y2/`, `benchmark/phase_y2_3/`, `benchmark/phase_y3/`, `benchmark/phase_y_prospective/`, `sentinel-y/`.

Esto indica que **estos artefactos no están versionados** en el repositorio actual. Antes de declarar el motor como candidato sellado, se deben:
1. Añadir al control de versiones los artefactos de esta fase (motor v0.3, harness, resultados, summary, hashes, registro de selección).
2. Confirmar que v0.1/v0.2 permanecen sin cambios (hashes arriba).

Los hashes de v0.1/v0.2 demuestran integridad del archivo; **no** demuestran compromiso de custodia en Git hasta que los artefactos estén versionados.
