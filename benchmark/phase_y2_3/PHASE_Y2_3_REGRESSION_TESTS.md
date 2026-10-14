# PHASE_Y2_3_REGRESSION_TESTS.md — Sentinel Y v0.3

Suite de aceptación ejecutable: `benchmark/phase_y2_3/run_phase_y2_3_acceptance.js`
Salidas: `PHASE_Y2_3_RESULTS.jsonl`, `PHASE_Y2_3_METRICS.json`

Ejecución:
```
node benchmark/phase_y2_3/run_phase_y2_3_acceptance.js
```

## Contrato de la suite
- Motor bajo prueba: `sentinel-y/v0.3` (`version === '0.3.0'`).
- No modifica v0.1/v0.2 ni evidencia histórica.
- Las regresiones de calibración se leen en tiempo de ejecución desde las revisiones vulnerables fijadas con `git show <sha>:<file>`; no se duplican contenidos en el repo.
- Cada bloque se evalúa y reporta por separado; no se mezclan métricas.

## Bloque 1 — Contraejemplos (CE-01..CE-05)
| ID | Código bajo prueba | Regla | Criterio de aceptación |
| --- | --- | --- | --- |
| CE-01 | `for (let key in obj) { target[key] = null; }` | Y-PROTO-001 | Debe disparar; NO debe ser CONFIRMED |
| CE-02 | `Service.prototype[m] = function(){...}` sobre `for..in` | Y-PROTO-001 | Debe disparar (no supresión); NO CONFIRMED |
| CE-03 | `for (let p in path) { obj[p] = true; }` | Y-PROTO-001 | Debe disparar; NO debe ser CONFIRMED |
| CE-04 | `/ (a{0,256})* /` | Y-REDOS-001 | Debe disparar (finito anidado bajo `*`) |
| CE-05 | `/ (?=a+)(a+)+ /` | Y-REDOS-001 | Debe disparar (lookahead no neutraliza) |

## Bloque 2 — Regresiones de calibración
| ID | Paquete | Archivo | SHA vulnerable | Regla | Criterio |
| --- | --- | --- | --- | --- | --- |
| REG-deep-extend | deep-extend | `lib/deep-extend.js` | `9653940a75c2ef2b1a503b24cbadd707cccffa8c` | Y-PROTO-001 | ≥1 hallazgo |
| REG-mixin-deep | mixin-deep | `index.js` | `9925af763440a50891358d00db0e6a5accc50ee6` | Y-PROTO-001 | ≥1 hallazgo |
| REG-json5 | json5 | `src/parse.js` | `072eb402fc107a2f568ba78962d3d99de95032a9` | Y-PROTO-001 | ≥1 hallazgo (diagnóstico) |
| REG-tough-cookie | tough-cookie | `lib/cookie.js` | `fcc8abfa3d3cab4f99da38f3f3749b1b186eb5a4` | Y-REDOS-001 | ≥1 hallazgo |
| REG-cross-spawn | cross-spawn | `lib/util/escape.js` | `9521e2da94d94998f948e0455903e62d87884600` | Y-REDOS-001 | ≥1 hallazgo |

El cumplimiento de una regresión **no** demuestra generalización; solo confirma que el mecanismo conocido sigue detectándose.

## Bloque 3 — Controles benignos
PASS = 0 hallazgos CONFIRMED (se permite CANDIDATE).

| ID | Patrón | Esperado |
| --- | --- | --- |
| BEN-shallow-copy | Copia superficial sobre diccionario plano | No CONFIRMED |
| BEN-null-proto | `Object.create(null)` + copia | No CONFIRMED |
| BEN-regex-anchored | `/^[a-z]+$/` | Sin hallazgos |
| BEN-regex-bounded | `/\d{1,4}/` | Sin hallazgos |
| BEN-guarded-merge | Guarda completa de claves peligrosas | Sin hallazgos |

## Bloque 4 — Desconocidos / no soportados
PASS = no caída y 0 CONFIRMED.

| ID | Entrada |
| --- | --- |
| UNK-comment-only | `// nothing to analyse` |
| UNK-empty | Cadena vacía |
| UNK-partial-syntax | `function ( { for (let x in` |

## Bloque 5 — Determinismo
`DET-ce-repeat`: el bloque CE se ejecuta dos veces; los resultados serializados deben coincidir. PASS = estable.

## Trazabilidad contra límites conocidos
- `regexUsagePattern` sin flag `g` → bucle infinito corregido (ver `PHASE_Y2_3_SUMMARY.md`).
- Regresión de supresión CE-02 corregida (v0.2 emitía CLEAN; v0.3 emite CANDIDATE).
- Sobre-supresión CE-04/CE-05 corregida (cuantificador finito y lookahead ya no silencian).
- Sobre-confirmación acotada: las escrituras dinámicas sin ruta probada permanecen CANDIDATE; solo el deep-merge recursivo demostrado se confirma.
