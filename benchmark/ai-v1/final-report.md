# Sentinel AI Benchmark v1 — Final Synthesis & Architecture Report

## 1. Overview & Experimental Framing

- **Target Corpus:** 28 controlled engineering cases (N=28).
  - 6 malicious attack vectors from PR #12 (`scripts/health-check.js`, `scripts/report-utils.js`, `package.json`).
  - 20 verified benign modules (synthetic controls B01–B20).
  - 2 semantic evaluation variants (SP01a constant `eval` vs SP01b tainted `eval`).
- **Statistical Quality:** `LOW_MEDIUM_CONTROLLED_ENGINEERING_STUDY`.
- **Model:** `google/gemini-3.5-flash-lite`, temperature = 0.0 (deterministic mode).
- **Token Measurement:** `ACTUAL_TOKEN_MEASUREMENT = PASS` (real usage telemetries from provider metadata).

---

## 2. Global Results: Comparative Matrix

| Mode | Coverage | TP | TN | FP | FN | UNKNOWN | Precision (Global) | Recall (Global) | FPR (Global) | Total Tokens | Correct / 1k Tokens | Tool Calls |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **AI_ALONE** | 39.3% (11/28) | 6 | 4 | 1 | 0 | 17 | 85.7% | 85.7% | 4.8% | 13,321 | 0.75 | 0 |
| **SENTINEL_ASSISTED** | 100.0% (28/28) | 7 | 20 | 1 | 0 | 0 | 87.5% | 100.0% | 4.8% | 18,979 | 1.42 | 0 |
| **SENTINEL_AGENTIC (Pure)** | 64.3% (18/28) | 3 | 15 | 0 | 0 | 10 | 100.0% | 42.9% | 0.0% | 22,390 | 0.80 | 16 |
| **SENTINEL_HYBRID (Final)** | **100.0% (28/28)** | **7** | **21** | **0** | **0** | **0** | **100.0%** | **100.0%** | **0.0%** | **20,696** | **1.35** | **2** |

---

## 3. Semantic Pair Resolution

| Semantic Case | Ground Truth | AI_ALONE | SENTINEL_ASSISTED | SENTINEL_AGENTIC (Pure) | SENTINEL_HYBRID |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **SP01a** (`eval(constante)`) | **BENIGN** | CONFIRMED (FP ❌) | CONFIRMED (FP ❌) | BENIGN (TN ✅) | **BENIGN (TN ✅)** |
| **SP01b** (`eval(userInput)`) | **MALICIOUS** | CONFIRMED (TP ✅) | CONFIRMED (TP ✅) | UNKNOWN (UN ❌) | **CONFIRMED (TP ✅)** |

---

## 4. Key Engineering Conclusions

1. **AI Alone sufre de parálisis por ambigüedad:**
   - Sin escáneres estáticos de respaldo, el modelo se abstuvo en **17 de 28 casos** (`coverage = 39.3%`). No tiene bases para asegurar que un módulo es limpio.
2. **Sentinel-Assisted maximiza el rendimiento base:**
   - Resuelve el 100% de los casos ordinarios con solo **703 tokens por decisión correcta**. El expediente determinista le da el contexto necesario para declarar casos benignos como `BENIGN` con total confianza.
3. **Agentic Puro es excesivamente conservador:**
   - Si se fuerza a la IA a pedir herramientas para todo, genera tokens innecesarios (22.4k tokens) y un 35.7% de abstención por no poder cerrar la hipótesis sin interactividad de múltiples turnos.
4. **La Arquitectura Híbrida (`SENTINEL_HYBRID`) es la solución óptima:**
   - El 92.8% de los casos (26/28) se resuelven en la primera pasada con Sentinel-Assisted.
   - Solo los casos con **ambigüedad semántica de flujo / taint** (2/28) escalan al bucle interactivo de herramientas de Agentic.
   - **Resultado:** **100% Cobertura, 100% Precisión, 100% Recall, 0 FP, 0 FN, 0 UNKNOWN**.
