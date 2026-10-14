# PHASE_Y2_3_SPEC.md — Sentinel Y v0.3 Corrección Semántica (CE-01 a CE-05)

## Objetivo
Resolver CE-01–CE-05 manteniendo v0.2 como línea base histórica. Implementar v0.3.0 independiente, sin modificar archivos congelados (v0.1, v0.2). Sin ejecutar corpus prospectivo aún.

## Interfaz
`analyzeFile(filePath, content)` retorna array de findings con estructura compatible (ruleId, cwe, verdict, confidence, title, file, line, snippet, proofWitness).

## CE-01 — Reasignación prototipo con null
Caso: `function reassignProto(target, key) { for (let key in obj) { target[key] = null; } }`

Restricciones v0.3:
- No clasificar automáticamente escritura dinámica con valor `null` como contaminación CONFIRMED.
- Distinguir: (1) reasignación prototipo objeto individual, (2) modificación prototipo compartido, (3) inyección en `Object.prototype`, (4) peligrosidad indeterminable.
- Entrada no prueba `__proto__`; conservar incertidumbre si flujo de datos no demostrable.
- Resultado preferente: CANDIDATE con confidence MEDIUM/LOW cuando destino/ruta/prototipo compartido no se resuelve; CONFIRMED solo con evidencia demostrada.

## CE-02 — Inyección dinámica prototipo clase
Caso: `for (let m in userMethods) { Service.prototype[m] = function() { return userMethods[m]; }; }`
- Eliminar supresión incondicional de asignaciones a `.prototype`.
- Solo seguro con evidencia (claves restringidas + no sobrescritura peligrosa).
- Distinguir mutación prototipo de clase vs contaminación `Object.prototype`.
- No emitir CLEAN por valor función si confianza clave no demostrable.

## CE-03 — Escritura dinámica valor primitivo
Caso: `for (let p in path) { obj[p] = true; }`
- No confundir inocuidad booleano mapa plano con seguridad setter/rutas.
- No confirmar llegada a prototipo compartido sin evidencia.
- Limitar análisis rutas: escritura plana vs setter atraviesa ruta vs llegada demostrada a prototipo compartido vs ruta no resoluble.
- Si ruta no resoluble → CANDIDATE/incertidumbre con evidencia limitación.

## CE-04 — Cuantificador finito + repetición no acotada
Caso: `var r = /(a{0,256})*/;`
- Eliminar supresión global solo por `{0,`.
- Evaluar anidamiento: límite interno no elimina ambigüedad cuantificador exterior no acotado.
- Basar detección en estructura completa. Añadir controles finitos seguros y casos anidados peligrosos (evitar marcar todo acotado).

## CE-05 — Lookahead sin aislamiento repetición ambigua
Caso: `var r = /(?=a+)(a+)+/;`
- Eliminar supresión global por `(?=`.
- Evaluar si aserción modifica estructura relevante backtracking.
- Lookahead no neutraliza grupo ambiguo posterior automáticamente.
- Incluir casos donde sí mitiga y donde no.

## Pruebas aceptación (deterministas)
- CE-01–CE-05 con expectativa justificada + salida registrada + test automatizado
- Regressiones: deep-extend, mixin-deep, tough-cookie, cross-spawn
- json5 como regresión diagnóstica
- Negativos: asignaciones superficiales, objetos prototipo nulo, patrones regex estructuralmente seguros
- Casos inciertos/sintaxis no soportada
- No mezclar CANDIDATE con CONFIRMED
- Métricas por bloques: (1) regresiones calibración, (2) clasificación CE, (3) controles benignos, (4) desconocidos/no soportados, (5) reproducibilidad/determinismo
