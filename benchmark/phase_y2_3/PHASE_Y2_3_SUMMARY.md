# PHASE_Y2_3_SUMMARY.md — Sentinel Y v0.3 Acceptance

**Fase:** Y2.3 (aceptación del candidato v0.3)
**Motor:** sentinel-y v0.3.0 (Independent Semantic Edition)
**Estado:** Compuertas de aceptación superadas. **DETENIDO antes del benchmark prospectivo.**

## Identidades de artefacto (SHA-256)
| Artefacto | SHA-256 |
| --- | --- |
| `sentinel-y/v0.1/index.js` (congelado) | `175004F5AE9E110929D445B27AC9FF40A6AE0EB7B2C8F04CEBDFD6F520905A28` |
| `sentinel-y/v0.2/index.js` (congelado) | `AC9BECBE913B2114120EF5A33D889A869C25B583252836E7D3C0EEC7597B83C8` |
| `sentinel-y/v0.3/index.js` (candidato) | `93B9534F6C4F51782A00FAD478D553AD545FD6D18314EB3B82FF3134461D1E54` |

v0.1 y v0.2 se verificaron sin cambios respecto a los hashes congelados. v0.3 vive en un módulo separado; no se tocó Sentinel Cloud/X/Audit Core/CLI/Oracle ni `@sentinel/cloud-client`.

## Bloque 1 — Contraejemplos CE-01..CE-05 (precisión de clasificación)
Cada contraejemplo tiene expectativa justificada, resultado observado y test automatizado en `run_phase_y2_3_acceptance.js`.

| ID | Familia | Regla | Expectativa | Observado | Confianza | Resultado |
| --- | --- | --- | --- | --- | --- | --- |
| CE-01 | Prototype Pollution | Y-PROTO-001 | Fuego, sin CONFIRMED | Fuego, CANDIDATE | LOW | PASS |
| CE-02 | Prototype Pollution | Y-PROTO-001 | Fuego (no suprimir), sin CONFIRMED | Fuego, CANDIDATE | MEDIUM | PASS |
| CE-03 | Prototype Pollution | Y-PROTO-001 | Fuego, sin CONFIRMED | Fuego, CANDIDATE | LOW | PASS |
| CE-04 | ReDoS | Y-REDOS-001 | Fuego (cuantificador finito anidado bajo `*`) | Fuego, CONFIRMED | HIGH | PASS |
| CE-05 | ReDoS | Y-REDOS-001 | Fuego (lookahead no neutraliza) | Fuego, CANDIDATE | MEDIUM | PASS |

- CE-01/CE-03: escrituras dinámicas cuyo camino al prototipo compartido no está probado → CANDIDATE (no se confirma peligrosidad no demostrada).
- CE-02: la inyección en `Service.prototype[...]` ya no se suprime (regresión de supresión de v0.2 corregida); se emite con incertidumbre.
- CE-04: `(a{0,256})*` — el cuantificador finito interno ya no suprime la ambigüedad del `*` externo → CONFIRMED.
- CE-05: `(?=a+)(a+)+` — la presencia de lookahead no neutraliza el grupo ambiguo posterior → CANDIDATE (se degrada de CONFIRMED a CANDIDATE conforme a la nueva regla de lookahead).

## Bloque 2 — Regresiones de calibración
Leídas desde las revisiones vulnerables fijadas (`benchmark/phase5/PHASE5_MANIFEST.json`).

| ID | Paquete | Archivo | SHA vulnerable | Regla | Hallazgos | Veredictos | Resultado |
| --- | --- | --- | --- | --- | --- | --- | --- |
| REG-deep-extend | deep-extend | `lib/deep-extend.js` | `9653940a75c2ef2b1a503b24cbadd707cccffa8c` | Y-PROTO-001 | 9 | CANDIDATE, CONFIRMED | PASS |
| REG-mixin-deep | mixin-deep | `index.js` | `9925af763440a50891358d00db0e6a5accc50ee6` | Y-PROTO-001 | 3 | CONFIRMED, CANDIDATE | PASS |
| REG-json5 | json5 | `src/parse.js` | `072eb402fc107a2f568ba78962d3d99de95032a9` | Y-PROTO-001 | 1 | CONFIRMED | PASS |
| REG-tough-cookie | tough-cookie | `lib/cookie.js` | `fcc8abfa3d3cab4f99da38f3f3749b1b186eb5a4` | Y-REDOS-001 | 2 | CONFIRMED | PASS |
| REG-cross-spawn | cross-spawn | `lib/util/escape.js` | `9521e2da94d94998f948e0455903e62d87884600` | Y-REDOS-001 | 2 | CONFIRMED | PASS |

- deep-extend y mixin-deep confirman el mecanismo de deep-merge recursivo (`target[key] = deepExtend/extend/mixin(...)`) cuando no hay guarda completa.
- json5 confirma la escritura dirigida por ruta auto-recursiva (`const replacement = internalize(value, key, reviver)` seguido de `value[key] = replacement`). Un control temprano de esta corrida la había degradado a CANDIDATE; se corrigió y ahora CONFIRMA.
- tough-cookie y cross-spawn confirman ReDoS por cuantificador anidado.
- Criterio de regresión: un caso de calibración no diagnóstico solo satisface la compuerta con un veredicto **CONFIRMED**. `PHASE_Y2_3_METRICS.json` reporta por separado `confirmed` y `candidateOnly`.

## Bloque 3 — Controles benignos (no sobre-confirmar)
PASS = 0 hallazgos CONFIRMED.

| ID | Descripción | Hallazgos | CONFIRMED | Veredictos | Resultado |
| --- | --- | --- | --- | --- | --- |
| BEN-shallow-copy | Copia superficial sobre diccionario plano | 1 | 0 | CANDIDATE | PASS |
| BEN-null-proto | Mapa sobre objeto de prototipo nulo | 1 | 0 | CANDIDATE | PASS |
| BEN-regex-anchored | Regex anclada lineal `/^[a-z]+$/` | 0 | 0 | — | PASS |
| BEN-regex-bounded | Cuantificador finito sin anidamiento `/\d{1,4}/` | 0 | 0 | — | PASS |
| BEN-guarded-merge | Guarda completa `__proto__`/`constructor`/`prototype` | 0 | 0 | — | PASS |

## Bloque 4 — Desconocidos / no soportados
PASS = sin caída y 0 CONFIRMED.

| ID | Entrada | Caída | Hallazgos | Resultado |
| --- | --- | --- | --- | --- |
| UNK-comment-only | Solo comentario | No | 0 | PASS |
| UNK-empty | Archivo vacío | No | 0 | PASS |
| UNK-partial-syntax | Sintaxis parcial | No | 0 | PASS |

## Bloque 5 — Reproducibilidad / determinismo
`DET-ce-repeat`: el bloque CE se ejecuta dos veces; salidas idénticas byte a byte → **PASS** (estable).

## Métricas (por bloque, no mezcladas)
```json
{
  "counterexamples": { "passed": 5, "total": 5 },
  "regressions":     { "passed": 5, "total": 5, "confirmed": 5, "candidateOnly": 0 },
  "benign_controls": { "passed": 5, "total": 5 },
  "unknown":         { "passed": 3, "total": 3 },
  "determinism":     { "passed": 1, "total": 1 }
}
```
La métrica de regresiones separa `confirmed` de `candidateOnly`; un caso no diagnóstico con solo CANDIDATE no cuenta como PASS.

## Verificación del caso json5 (señalado en revisión)
Se detectó que un control temprano de esta corrida evaluaba json5 como CANDIDATE, frente al CONFIRMED de v0.1/v0.2. Verificación:
- Expectativa del harness: json5 quedó como regresión no diagnóstica → exige CONFIRMED.
- v0.1 = CONFIRMED, v0.2 = CONFIRMED, v0.3 (control temprano) = CANDIDATE → **regresión funcional real**.
- Causa: la escritura `value[key] = replacement` toma su valor de la llamada auto-recursiva `internalize(value, key, reviver)` en la misma vuelta del bucle; la rama genérica de v0.3 no reconocía la auto-recursión (solo deep-merge explícito).
- Corrección: se rastrea la función envolvente del bucle y se detecta que el valor asignado proviene de una llamada de la propia función → `RECURSIVE_DEEP_MERGE` (CONFIRMED).
- Los contraejemplos CE-01..CE-05 no tienen auto-recursión y permanecen en su clasificación (CE-01/02/03 CANDIDATE; CE-04 CONFIRMED; CE-05 CANDIDATE), por lo que no se reintroduce sobre-confirmación.

## Correcciones de implementación en v0.3
- `regexUsagePattern` pasó a ser global (`/g`) y se resetea su `lastIndex` por línea. Su falta de flag `g` causaba un **bucle infinito** en el `while` (hang/OOM) al analizar archivos con una llamada `x.replace|match|test|exec(`.
- Los patrones `regexLiteralPattern` y `regexUsagePattern` resetean `lastIndex = 0` antes de cada `while`.
- Detección de cuantificador anidado: grupo con cuantificador interno + cuantificador externo `[+*]` (ya no requiere que el grupo sea finito).
- Lookahead: ya no neutraliza la detección; degrada el veredicto CONFIRMED→CANDIDATE.
- Deep-merge recursivo demostrado (`mixin(...)`, `deepExtend(...)`, `extend(...)`) o escritura cuyo valor proviene de una llamada auto-recursiva de la función envolvente → CONFIRMED; escritura dinámica con ruta al prototipo no resuelta → CANDIDATE.
- `regexUsagePattern` global + reset por línea evita el bucle infinito al analizar archivos grandes (tough-cookie).

## Cierre
Compuertas de aceptación v0.3 **superadas**. Se registra la identidad de v0.3. **No se ejecuta el benchmark prospectivo** (requiere custodio independiente, corpus disjunto y ground truth bajo custodia separada — ver `ENGINE_SELECTION_RECORD.md`).

## Alcance
Resultados observados sobre el corpus de aceptación (contraejemplos + regresiones de calibración + controles). No demuestran generalización sobre un corpus prospectivo no visto.
