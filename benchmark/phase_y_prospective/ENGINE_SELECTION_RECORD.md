# ENGINE_SELECTION_RECORD.md — Sentinel Y v0.3 Candidate Selection

**Scope:** Phase Y prospective evaluation (pre-sellado). No ejecutado todavía.

## 1. Motores congelados (SHA-256)
- sentinel-y/v0.1/index.js — 175004F5AE9E110929D445B27AC9FF40A6AE0EB7B2C8F04CEBDFD6F520905A28
- sentinel-y/v0.2/index.js — AC9BECBE913B2114120EF5A33D889A869C25B583252836E7D3C0EEC7597B83C8

## 2. Candidato v0.3
- Ruta: sentinel-y/v0.3/index.js
- Versión: 0.3.0 (Independent Semantic Edition)
- SHA-256: 93B9534F6C4F51782A00FAD478D553AD545FD6D18314EB3B82FF3134461D1E54
- Estado: Implementado (Fase 2 completa) y **aceptación Y2.3 superada** (Fase 3). Candidato con identidad registrada; **no sellado** hasta designar custodio independiente y cerrar compuertas de custodia.
- Evidencia de aceptación: `benchmark/phase_y2_3/PHASE_Y2_3_SUMMARY.md`, `PHASE_Y2_3_RESULTS.jsonl`, `PHASE_Y2_3_METRICS.json`, `PHASE_Y2_3_REGRESSION_TESTS.md`.

## 3. Custodia
- Custodio independiente: TBD (requerido antes de sellado ciego)
- Manifesto Ground Truth: TBD (bajo custodia separada)

## 4. Compromisos de integridad
- v0.1/v0.2 no modificados. Archivos congelados preservados.
- v0.3 implementado en módulo separado.
- No selección/ejecución del corpus prospectivo aún.
- Evidencia histórica (calibración, Y3, 5 contraejemplos CE-01–CE-05) permanece inmutable.

## 5. Compuertas (previas a sellado)
- [x] Cada CE-01–CE-05 con expectativa justificada, resultado observado y test automatizado
- [x] Regresiones calibración + controles benignos + casos inciertos + sintaxis no soportada
- [ ] Custodio independiente designado
- [ ] Corpus disjunto seleccionado
- [ ] Ground truth bajo custodia separada
- [ ] Hash definitivo v0.3 registrado
- [ ] Hash y sello del manifiesto registrados
- [ ] Cumplimiento verificado

**Estado actual:** Fases 1–3 completadas (implementación + aceptación v0.3, 24/24 checks PASS). **DETENIDO antes de ejecutar benchmark prospectivo**, a la espera de custodio independiente, corpus disjunto y ground truth bajo custodia separada.
