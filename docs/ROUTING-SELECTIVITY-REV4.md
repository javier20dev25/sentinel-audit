# ROUTING SELECTIVITY: Rev.4 (controlado)

Cohorte: 5 repos publicos reales, pins exactos de Rev.2, Semgrep 1.175.0.
Fuente: artefactos Rev.2 recuperados en `%TEMP%\opencode\cloud-calibration-5\out\`.
**No se relanzo Sentinel Cloud. No se toco el motor, ni Purple, ni Oracle.**

## Veredicto

**HOLD. Caso B no pasa el gate de recall.** La shortlist recorta la superficie de forma
extrema (96.2% menos archivos) y aun asi pierde 2 de 14 hallazgos de Semgrep (85.7% de
recall agregado, 50% en express). Las perdidas son silenciosas: Cloud reporto AMPLIFY
con `engineIncomplete=false` y sin ninguna marca de que el 96.2% del repo quedo fuera.
No hay base para llamar "limpio" a un veredicto routed, ni para lanzar la campana 50+.

## Por que hubo que repetir Rev.2

Rev.2 no midio lo que creia medir. Tres defectos, los tres medidos en esta corrida:

1. **El tope de 40 archivos.** `audit-runner.js:112` define `maxScopeFiles=40`,
   `workflow/audit.js:154` lo pasa como `maxTargets`, y `adapters/index.js:191` corta la
   lista. Como las 5 shortlists tienen mas de 40 archivos, Semgrep solo vio los primeros
   40 de cada una: **200 de 413 archivos promovidos (48.4%)**. Rev.2 registro 6 hallazgos
   Semgrep; la shortlist completa produce 12. Express 2 vs 2, fastify 0 vs 1, svelte 2 vs 7,
   flags 1 vs 1, swr 1 vs 1.
2. **`semgrep.coverage.filesParsed` no era cobertura.** `adapters/index.js:220` lo llena con
   `ctx.inv.sourceFiles` (el inventario del repo), no con `paths.scanned` de Semgrep. Rev.2
   reporto cerca del 100% de cobertura sin haber escaneado mas de 40 archivos.
3. **El recall de 13/18 de Rev.3 no era de routing.** CodeQL se invoca sin scope
   (`workflow/audit.js:152`) y `correlate/index.js` nunca recibe la shortlist. Los 15
   candidatos CodeQL son repo-level por construccion; su scope no lo define Cloud.

Ademas, el escaneo por directorio de Semgrep resulto ser un denominador invalido
(ver "punto ciego" abajo), lo que obliga a un tercer brazo explicito.

## Diseno: tres brazos, una sola variable

Unica variable: **el conjunto de targets**. Mismo repo, commit, tree, version de Semgrep,
rulesets (`p/security-audit`, `p/secrets`) y flags en los tres brazos.

| Brazo | Targets | Proposito |
|---|---|---|
| **A** | directorio del repo | mecanismo *unscoped* real (`adapters/index.js:189`). Par justo de **tiempo** |
| **B** | shortlist promovida, sin tope | brazo **routed** (lo que la produccion quiso hacer) |
| **F** | los 9k+ archivos versionados, en lotes de 300 | unico brazo con universo conocido. **Denominador de recall** |

A y B usan 1 proceso por config. F usa hasta 62, asi que **el wall time de F no se usa
para ninguna conclusion de ahorro**.

## Tabla final

| repo | F files | B files | red. | F finds | B finds | recall | A ms | B ms | tiempo |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| expressjs__express | 214 | 45 | 79.0% | 4 | 2 | **50.0%** | 49632 | 43713 | 11.9% |
| fastify__fastify | 395 | 126 | 68.1% | 1 | 1 | 100% | 50217 | 49246 | 1.9% |
| sveltejs__svelte | 9095 | 76 | 99.2% | 7 | 7 | 100% | 64945 | 43509 | 33.0% |
| vercel__flags | 802 | 106 | 86.8% | 1 | 1 | 100% | 61242 | 45098 | 26.4% |
| vercel__swr | 347 | 60 | 82.7% | 1 | 1 | 100% | 51941 | 44301 | 14.7% |
| **TOTAL** | **10853** | **413** | **96.2%** | **14** | **12** | **85.7%** | **277977** | **225867** | **18.7%** |

`red.` = reduccion de archivos de B contra el universo F. `tiempo` = A contra B.

### El tiempo no es la metrica relevante

B tarda 43.5s a 49.2s sea cual sea el tamano de la shortlist (45 archivos o 126). A tarda
49.6s a 64.9s y si escala con los archivos. La razon: **~22s de arranque por proceso
Semgrep**, 2 procesos por repo. El 18.7% de ahorro es mayoritariamente coste fijo, no
trabajo eliminado. La reduccion real de trabajo es la de superficie: 96.2%.

## Punto ciego: el escaneo por directorio no es un denominador

| repo | A escanea | universo F | % | A findings | F findings |
|---|---:|---:|---:|---:|---:|
| express | 102 | 214 | 47.7% | 4 | 4 |
| fastify | 158 | 395 | 40.0% | **0** | 1 |
| svelte | 645 | 9095 | 7.1% | 7 | 7 |
| flags | 688 | 802 | 85.8% | 1 | 1 |
| swr | 205 | 347 | 59.1% | 1 | 1 |

Apuntar al directorio `test/` explicito **no** cambia nada: Semgrep lo sigue saltando.
Apuntar a los archivos si. Express: 0 de 19 archivos de test de B. Fastify: 0 de 93.
El hallazgo unico de fastify esta en `test/server.test.js:102` y el escaneo por directorio
no lo ve. **A recall 92.9% del universo, y A no es superconjunto de B**, por eso el brazo F.

## Curva de sensibilidad

Archivos promovidos necesarios para alcanzar cada objetivo, ordenados por senal
accionable de Cloud descendente (campo existente, sin heuristica nueva):

| repo | 100% | 95% | 90% | nota |
|---|---|---|---|---|
| express | 45/45 | 45/45 | 45/45 | **no alcanza**: 50% con la shortlist entera |
| fastify | 87/126 | 87/126 | 87/126 | el unico hallazgo esta en un archivo de test |
| svelte | **12/76** | 12/76 | 12/76 | 0.13% del universo da el 100% |
| flags | 10/106 | 10/106 | 10/106 | 1.2% del universo |
| swr | 5/60 | 5/60 | 5/60 | 1.4% del universo |

Con 14 hallazgos en toda la cohorte, los umbrales 95% y 90% son degenerados (se colapsan en
100%). La curva sirve para repos con senal densa, no para estos cinco.

## Ledger de exclusiones falsas (gate 3)

Las 2 perdidas, con su causa:

| repo | archivo | linea | regla | sev | senal accionable de Cloud en el archivo |
|---|---|---:|---|---|---:|
| express | `examples/session/index.js` | 19 | `express-session-hardcoded-secret` | HIGH | 0 |
| express | `examples/session/redis.js` | 23 | `express-session-hardcoded-secret` | HIGH | 0 |

Clasificacion: **perdidas por routing**, no por politica. `/examples` no esta en la lista
de exclusiones de `correlate/index.js` (que es `/test` y `/benchmark`); Cloud simplemente no
emitio ninguna senal accionable en esos archivos, asi que nunca los promovio.

Riesgo real bajo: son demos con secretos de ejemplo, no codigo de produccion. Pero el
mecanismo no lo sabe. **El punto que importa no es estos dos archivos: es que un archivo con
un secreto HIGH puede caerse por completo sin dejar marca, porque el peso de la senal de
Sentinel y el disparador de la regla de Semgrep no tienen por que correlacionar.**

## Ledger de candidatos de Rev.2

| clase | n |
|---|---:|
| `RECOVERED` (encontrado en F y en B) | 3 |
| `LOST_BY_ROUTING` | 0 |
| `NOT_MEASURABLE_BY_SEMGREP` (CodeQL, repo-level) | 15 |

Los 3 medibles se recuperan: `SAR-0014` svelte `check-treeshakeability.js:90`,
`SAR-0015` svelte `migrate/index.js:363`, `SAR-0001` swr `bump-next-version.js:19`.

**El recall de candidatos de Rev.2 no es calculable con un experimento de Semgrep.** De los
18 candidatos, 15 los produjo CodeQL, que ya escanea el repo entero: su recall no lo define
la shortlist. Anyadir los 5 de svelte (experimento C) tampoco cambia el denominador.

## Experimento C: los 5 "candidatos fuera de la shortlist" de svelte

No son candidatas perdidas por el routing. Los 5 son hallazgos de **CodeQL**
(`js/polynomial-redos`), y CodeQL no se scopea: recorrio el repo entero. Los 5 archivos
tienen 0 senales de Cloud, pero eso no impidio que CodeQL los encontrara, precisamente
porque CodeQL no consulta la shortlist.

De los 24 hallazgos especialistas que produjo esa pasada, 18 llegaron a
candidato y 6 quedaron fuera: 5 en `test/` y 1 en `benchmarking/`, por la politica de
no-produccion. Clasificacion correcta: **CodeQL especialista, no recall de routing**.

## Experimento D: los controles de Fastify y el caso SVELTE-CORR-01

Localizados en `supply-chain/triage/TRIAGE-REPORT.md`, no inferidos:

- **FASTIFY-01** `lib/content-type.js:158,176` y **FASTIFY-02** `lib/request.js:267`. En los
  tres casos la regex es literal (`/^text\/(\w+)(?:;...` y `/^\s*$/`), y el finding esta en
  la linea 158 frente a la 176, y 267 frente a 266. Ambos archivos **si** estaban promovidos
  con 2 senales cada uno. CodeQL y Semgrep dieron 0 correctamente. Adjudicados
  `FALSE_POSITIVE`: el clasificador etiqueta como `kind=exec` cualquier metodo `.exec`, sin
  comprobar que sea `child_process.exec`. Confianza HIGH.
- **SVELTE-CORR-01** `benchmarking/compare/index.js:63`, `js/indirect-command-line-injection`.
  Detectado por CodeQL **tanto en Rev.2 como en la corrida historica**, y el archivo si
  estaba promovido. Se excluyo por la politica `/benchmark` (no produccion). Eso es una
  exclusion por politica, no un fallo de routing.

Los controles nombrados de Rev.3 ya no son `NOT_COMPUTABLE`.

## Gates

| # | Gate | Resultado | Evidencia |
|---|---|---|---|
| 1 | Reproducible | **PASS** | mismos pins, version, rulesets y flags. Determinismo verificado con una segunda ejecucion independiente de B en express (2/2 hallazgos identicos) y svelte (7/7 identicos), con wall time distinto (43713 vs 44592 ms) |
| 2 | Recall >= 90% en el umbral | **FAIL** | 85.7% agregado; 50% en express. La curva muestra que express **no puede** alcanzar 100/95/90 ni con la shortlist completa |
| 3 | Ledger de exclusiones falsas | **PASS** | 2 exclusiones identificadas, con archivo, linea, regla, severidad y causa |
| 4 | No producir "limpio" falso | **FAIL** | las 2 perdidas son silenciosas. `signalRouting.decision=AMPLIFY` con `engineIncomplete=false` y sin marcador de cobertura. Falta `filesScanned/totalTracked` en el veredicto |
| 5 | Campana 50+ | **HOLD** | no se lanza. Gate 2 en FAIL |

## Conclusión (<=10 lineas)

1. La shortlist recorta 96.2% de los archivos (10853 -> 413) y aun asi no es un superconjunto.
2. Recall de hallazgos Semgrep: 85.7% agregado; express cae a 50%.
3. Las 2 perdidas son secretos HIGH en `examples/`, con 0 senales de Cloud: riesgo real bajo, mecanismo sin garantia.
4. Un archivo con un secreto HIGH puede caerse por completo y sin dejar marca en el veredicto.
5. La reduccion de tiempo (18.7%) es sobre todo coste fijo de arranque de Semgrep, no trabajo eliminado.
6. Rev.2 estaba mal medido: el tope de 40 archivos vio 200 de 413 promovidos (48.4%) y registro 6 de 12 hallazgos.
7. El recall de los 18 candidatos de Rev.2 no es calculable aqui: 15 son CodeQL, que ya escanea el repo entero.
8. Los 5 casos de svelte y los 2 controles de Fastify no son fallos de routing: son CodeQL repo-level y falsos positivos adjudicados.
9. Gate 2 en FAIL y gate 4 en FAIL. No hay veredicto "limpio" defendible sobre la superficie no escaneada.
10. **HOLD.** No campana 50+. Requiere marcador de cobertura en el veredicto y una politica de recall declarada por engine.

## Que haria falta para convertir esto en verde

Sin engineering for green, esto es lo que la evidencia exige:

1. El veredicto routed debe llevar siempre `filesScanned/totalTracked` y el termino debe ser
   "limpio en la superficie promovida", nunca "limpio".
2. `maxScopeFiles` debe subir o el routing debe declarar cuanto de la shortlist se escaneo.
   Hoy un repo con 106 archivos promovidos escanea 40 y no lo dice.
3. La exclusion por peso de senal necesita ser explicita en el artefacto: hoy
   `engineIncomplete=false` afirma cobertura que no existia.
4. Fijar el recall esperado por engine, porque CodeQL es repo-level y Semgrep routed no lo es.
   Compararlos en un mismo numero de recall no significa nada.

## Reproducir

```
cd %TEMP%\opencode\cloud-calibration-5\ab
node harness.js <repo> A|B|F   # A=directorio, B=shortlist, F=universo completo
node aggregate.js               # regenera los JSON y la tabla
```

`AB_BATCH` controla el tamano de lote de F. `AB_FORCE=1` fuerza reejecucion. El harness
guarda cada corrida en `parts/` y es reanudable: una muerte a mitad no descarta el trabajo.

## Limites declarados

- Un solo detector (Semgrep) y cinco repos. El recall de un detector no es el recall de otro.
- 14 hallazgos en total. Las cifras de recall tienen granularidad gruesa.
- 64 archivos de svelte con `$` en la ruta quedaron fuera de F: Semgrep aborta el lote
  entero con `Invalid scanning root`. Registrados como `rejectedDollarPaths` en los JSON.
  Ninguno estaba en la shortlist de Rev.2.
- Semgrep reporta el mismo hallazgo una vez por ruleset que lo contiene. Svelte: 11 raw, 7
  unicos. Todos los conteos de este informe deduplican por ruta+linea+regla.
- Sin hash del ruleset resuelto: ambos brazos usaron los mismos `p/...` del registro, pero
  una reejecucion futura con reglas actualizadas no esta congelada.
- `PRODUCTION_PARITY` sigue sin medir. Este documento no dice nada sobre si la
  implementacion de produccion se parece a estos brazos.
