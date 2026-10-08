# HANDOFF TÉCNICO PARA OPENCODE — ECOSISTEMA SENTINEL & ARQUITECTURA HÍBRIDA

**Fecha:** 2026-10-07  
**Estado:** `BENCHMARK_V1_FROZEN = PASS` | `STAGE: NEXT = PRODUCTIZATION`  
**Commit Congelado en Audit:** `f3a36f4173ce246aa89c3caec5235904045cd280`

---

## 1. Aclaración Conceptual: Ecosistema vs. Modos de IA

Para evitar cualquier confusión terminológica al orquestar o programar:

### Las Herramientas del Ecosistema (Motores de Software):
- **`Sentinel CLI`** (`C:\Users\sleyt\sentinel-cli`): Motor sintáctico y SAST estático local/offline. Rápido (~2s). No requiere internet.
- **`Sentinel Oracle`** (`C:\Users\sleyt\sentinel-oracle`): Escáner y gate estricto de Pull Requests (Lite Scanner / `scan.ts`). Evalúa diffs y decide si bloquear o admitir cambios.
- **`Sentinel Cloud`** (`https://sentinel-psi-nine.vercel.app`): Backend en la nube (Vercel + Supabase + Render worker). Provee **threat intelligence enriquecida**, mapeando dominios maliciosos reales (C2 como `telemetry-analytics.xyz`), persistencia y correlación multi-señal.
- **`Sentinel Audit`** (`C:\Users\sleyt\sentinel-audit`): **Orquestador central determinista**. Ejecuta en dos fases:
  - *Etapa A:* Escaneo de superficie (Cloud o local).
  - *Etapa B:* Ruteo selectivo de especialistas pesados (`codeql`, `semgrep`, `trivy`, `osv`) solo si hay señales accionables justificadas.

### Los Modos Experimentales de IA:
- **`AI Alone`**: La IA evaluando código en crudo **sin ninguna ayuda ni herramienta de Sentinel**.
  - *Problema:* Sufre de **parálisis por ambigüedad** (17 abstenciones `UNKNOWN` de 28 casos, cobertura 39.3%).
- **`Sentinel Assisted`**: La IA recibe el **expediente procesado por Audit** (hallazgos normalizados, candidatos y evidencias). Resuelve en una sola llamada sin correr herramientas por su cuenta.
  - *Rendimiento:* Cobertura 100%, 27/28 aciertos, ~703 tokens por decisión correcta.
- **`Sentinel Agentic`**: La IA recibe el expediente y tiene permiso de pedir herramientas interactivas (`inspect_source`, `inspect_dataflow`).
  - *Problema:* Usado ciegamente en todo, es lento, gasta más tokens y tiene tendencia a abstenerse si no hay interactividad continua.
- **`Sentinel Hybrid` (La Arquitectura Oficial):**
  - **Flujo:** La vía determinista (`Audit + Cloud`) procesa primero. Si el expediente es claro, `Assisted` cierra el veredicto inmediatamente sin gastar herramientas.
  - **Escalamiento:** Solo si hay **ambigüedad semántica o de flujo de datos** (ej. `eval(constante)` vs `eval(userInput)`), se escala selectivamente a `Agentic` para ejecutar herramientas dirigidas (`inspect_dataflow`).
  - *Resultado:* **100% Cobertura, 100% Precisión, 100% Recall, 0 FP, 0 FN, 0 UNKNOWN** con solo 2 llamadas a herramientas en todo el corpus (reducción del 87.5%).

---

## 2. Mapa de Repositorios y SHAs Congelados

| Componente | Ruta Local en Windows | Rama | Commit SHA Congelado |
| :--- | :--- | :---: | :--- |
| **`sentinel-audit`** | `C:\Users\sleyt\sentinel-audit` | `main` | `f3a36f4173ce246aa89c3caec5235904045cd280` |
| **`sentinel-cli`** | `C:\Users\sleyt\sentinel-cli` | `master` | `360919364dff4f220caa26c1198ba878cf0a3f76` |
| **`sentinel-oracle`** | `C:\Users\sleyt\sentinel-oracle` | `main` | `292123e1e2be22781c0184eb444c1b6be9f1840a` |
| **`sentinel-cloud-client`** | `C:\Users\sleyt\sentinel-cloud-client` | `main` | `924d25d2362545fb58a39189d941f64404614093` |
| **`sentinel-cloud`** | `C:\Users\sleyt\sentinel-cloud` | `main` | `ebc469ae9797f269f4cc20c1b322260e97bc0b7a` |

---

## 3. Artefactos del Benchmark v1 (Para Paper y Auditoría)

Ubicados en `C:\Users\sleyt\sentinel-audit\benchmark\v1\`:
- [final-report.md](file:///C:/Users/sleyt/sentinel-audit/benchmark/v1/final-report.md): Reporte técnico oficial con fórmulas estrictas y comparativas.
- [methodology.md](file:///C:/Users/sleyt/sentinel-audit/benchmark/v1/methodology.md): Protocolo experimental, ground truth (N=28) y fórmulas de métricas.
- [metrics.json](file:///C:/Users/sleyt/sentinel-audit/benchmark/v1/metrics.json): Métricas en JSON consolidado estructurado.
- [MANIFEST.json](file:///C:/Users/sleyt/sentinel-audit/benchmark/v1/MANIFEST.json): Hashes de system prompts, SHA del commit y lista de casos.
- [comparison.csv](file:///C:/Users/sleyt/sentinel-audit/benchmark/v1/comparison.csv): Tabla caso por caso con tokens y tiempos.
- [hybrid_runs.jsonl](file:///C:/Users/sleyt/sentinel-audit/benchmark/v1/hybrid_runs.jsonl): Registros con telemetría nativa de tokens del proveedor.

---

## 4. Tareas Inmediatas de Productización (Plan de 7 Etapas)

### Regla Fundamental:
**NO hacer tuning a los motores deterministas existentes (CLI, Oracle, Cloud, Audit) basándose en los resultados del benchmark.** El benchmark V1 es el baseline congelado.

### Secuencia de Trabajo para OpenCode:
1. **Etapa 1 — Productizar Hybrid en Audit (`sentinel-audit`):**
   - Incorporar la lógica de decisión de [benchmark/ai-v1/hybrid-runner.js](file:///C:/Users/sleyt/sentinel-audit/benchmark/ai-v1/hybrid-runner.js) dentro del pipeline oficial de Audit (`workflow/pipeline-v1.js` o módulo de triage).
   - Política: *Deterministic first $\to$ if resolved: no AI $\to$ if ambiguous: targeted agentic tool loop $\to$ else: human review*.
2. **Etapa 2 — Crear Repositorio de Orquestación (`sentinel-ecosystem`):**
   - No meter todas las skills dentro de `sentinel-audit`. Crear `sentinel-ecosystem` para albergar las skills de orquestación (`sentinel-ecosystem-orchestrator`, `sentinel-audit-triage`, `sentinel-pr-review`, `sentinel-benchmark-runner`) y schemas de guardrails de seguridad (read-only enforcement, tool limits).
3. **Etapa 3 — Unificar Clientes:**
   - Migrar `sentinel-cli` (`cloud_client.ts`) para que consuma `@sentinel/cloud-client` unificado.
4. **Etapa 4 — Observabilidad de Producción:**
   - Instrumentar telemetría en Vercel, Supabase y Render worker antes del stress testing.
5. **Etapas 5 a 7 — Campaña a Gran Escala y Paper:**
   - Ejecutar stress tests por niveles (10 $\to$ 50 $\to$ 200 $\to$ 500 $\to$ 1000 scans) sobre corpus masivos (NPMStudy, OWASP, bug bounty), congelar **Ecosystem V2**, y redactar el paper científico basado en los datos empíricos observados.
