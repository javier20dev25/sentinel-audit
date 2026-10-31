# Revisión de cobertura y producto de Sentinel Audit

**Revisión del código:** 31 de octubre de 2026  
**Alcance:** CLI, interfaz `sentinel-audit web`, pipeline v1, adaptadores y configuración. No ejecuté escaneos contra repositorios objetivo.

## Lectura ejecutiva

Sentinel Audit ya tiene buenas bases de custodia: fija el SHA del PR, conserva salida cruda y normalizada, registra estados de cobertura, separa observaciones de candidatos, correlaciona señales y deja la decisión de divulgación en manos de una persona. La interfaz web puede convertir esa evidencia en una consola de investigación clara.

La cobertura efectiva, sin embargo, es menor que lo que sugiere el inventario de herramientas. El modo Lite de la web analiza el **diff del PR** con el analizador rápido integrado y pasa sus señales al pipeline. No invoca el motor local completo de Sentinel Cloud. Pulse sí envía el checkout fijado al servicio Sentinel Cloud configurado. El pipeline v1 usado por CLI y web conecta CodeQL, Semgrep, Trivy y OSV-Scanner, y ahora enruta Zizmor cuando el commit contiene definiciones CI/CD rastreadas. Bandit y ShellCheck están declarados y tienen adaptadores heredados, pero no pertenecen al conjunto ejecutado por v1.

La correlación tampoco mide probabilidad: `confidence: medium/high` cuenta autoridades independientes según la política. El cambio local en el triage elimina las decisiones automáticas de “confirmado” o “falso positivo”; su sondeo regex ahora queda como pista y conserva el caso para revisión humana.

## Modos y flujo observados

| Modo | Qué hace el código actual | Límite que debe quedar visible |
|---|---|---|
| `sentinel-audit web` + Lite | Consulta PR con `gh`, fija el SHA, obtiene el diff, ejecuta `liteScanner.auditPRDiff`, clona el head y ejecuta el pipeline con señales del diff como entrada. | Lite cubre el diff y sus reglas rápidas; no es una pasada completa del motor local ni una prueba de que el resto del repositorio esté limpio. |
| `sentinel-audit web` + Pulse | Usa la clave almacenada localmente y el endpoint de Sentinel Cloud cuando política, cliente, URL y clave están configurados. | Es un envío remoto deliberado del checkout fijado. La política viene desactivada por defecto; el producto debe indicar claramente qué código sale de la máquina. |
| Web + motor local | Fija el mismo SHA y ejecuta el motor Sentinel local configurado; Lite queda guardado aparte como referencia del diff. | Solo se ofrece cuando el preflight detecta el motor local completo. |
| CLI, pipeline v1 | Acepta ejecución local del motor configurado o proveedor Cloud; luego enruta especialistas, correlaciona candidatos y crea el expediente. | Los especialistas se escogen por señales y políticas; “no seleccionado” y “no ejecutado” deben seguir siendo estados explícitos. |

La interfaz web escucha en loopback, usa la sesión de `gh` del usuario y guarda expedientes en SQLite local. La vista de herramientas no debe confundirse con el registro de qué se ejecutó en un escaneo individual; para eso sirven la ruta y los estados por ejecución.

## Cobertura real de los analizadores

| Motor | Integración activa en v1 | Qué aporta | Límites / trabajo pendiente |
|---|---|---|---|
| Sentinel Audit Lite | Sí, en el flujo web de PR | Reglas rápidas sobre el diff, con archivo, línea y contexto disponible. | No sustituye al motor local completo, a CodeQL ni a un escaneo de todo el árbol. La pantalla ahora lo nombra como “Lite (PR diff)”. |
| Sentinel local completo | Sí en CLI y en el modo web “Motor local” cuando el preflight detecta el motor. | Señales del motor Sentinel instalado/configurado, separadas del resultado Lite del diff. | El panel presenta los tres modos como acciones distintas y registra el modo elegido en el expediente. |
| Sentinel Cloud Pulse | Sí, optativo | Análisis remoto configurado de Sentinel Cloud sobre el commit fijado. | Depende de política, cliente, URL y credenciales. La interfaz debe conservar consentimiento explícito y el límite de datos enviado. |
| CodeQL | Sí | Análisis estático con consultas de seguridad y rutas de flujo de datos en los lenguajes soportados por la suite. | La configuración incluida solo mapea suites para JavaScript, TypeScript y Python. No implica cobertura de todos los lenguajes que reconoce el inventario de repositorios. Un análisis CodeQL requiere que la extracción y la base terminen correctamente. |
| Semgrep | Sí | Reglas de patrones configurables y análisis estático sobre objetivos enrutados. | Esta configuración usa `rules/semgrep` y desactiva reglas remotas. Por eso no equivale a instalar y ejecutar el catálogo entero de Semgrep. Debe mostrarse la versión y el conjunto local de reglas usado. |
| zizmor | Sí, si el commit contiene workflows, acciones locales o configuración Dependabot rastreados | Audita definiciones de GitHub Actions/Dependabot en modo offline y conserva SARIF como evidencia. La ruta es independiente de las señales de código de Sentinel. | No evalúa comportamiento que solo ocurre en runtime ni scripts externos referenciados desde el YAML; sus auditorías online quedan desactivadas. La selección de archivos y el binario disponible se registran en el expediente. |
| Trivy | Sí, si la política enruta señales de dependencia/ciclo de vida | En esta configuración ejecuta `fs` con `vuln,secret,misconfig`; puede cubrir vulnerabilidades de paquetes, secretos en archivos y errores de configuración compatibles. | El escáner de licencias no está activado. El escaneo de secretos de archivos no sustituye un barrido del historial Git. La actualización de bases puede requerir red. |
| OSV-Scanner | Sí, si hay una señal de dependencia y el host lo permite | Compara manifiestos y lockfiles reconocidos con la base OSV. | Su cobertura depende de los ecosistemas y archivos admitidos y de que haya versiones resolubles. Corregí la atribución de archivo para usar `source.path` de OSV; cuando el motor no ofrece esa ruta queda sin archivo en vez de inventar `package.json`. |
| Bandit | No en el pipeline v1 activo | Análisis estático específico para Python; su adaptador heredado limita objetivos a archivos Python promovidos. | Está en inventario/configuración, pero `ALL_SPECIALISTS` de v1 no lo ejecuta. Debe integrarse al scheduler y al expediente antes de anunciarlo como cobertura activa. |
| ShellCheck | No en el pipeline v1 activo | Linter de shell; ayuda con defectos y endurecimiento de scripts. | No es un analizador de taint ni una autoridad para confirmar vulnerabilidades. Su adaptador heredado no está conectado a v1. |

CodeQL permite construir consultas de flujo fuente a destino, pero eso no significa que cada hallazgo de cualquier motor tenga una ruta de taint. La interfaz muestra `source`, `path`, `sink`, controles y bloqueos solo cuando la señal realmente los contiene; en otro caso declara que no hay ruta estructurada.

## Hallazgos de producto que corregí

- **Tema de la consola:** el archivo `theme.css` imponía colores claros sobre el tema oscuro base y la página declaraba `color-scheme: light`. La consola vuelve a una paleta oscura azul petróleo/cian, paneles con bordes definidos, mejor contraste y adaptación móvil.
- **Vista de evidencia:** separé candidatos correlacionados, observaciones no promovidas y señales individuales. El expediente muestra autoridades, nivel de corroboración, archivo/línea y los campos disponibles de `source → path → sink`; el modal conserva JSON normalizado, controles, bloqueos, asociaciones y pistas de triage.
- **Límite del triage anterior:** antes se derivaba `CONFIRMED` de severidad alta/crítica y `FALSE_POSITIVE` de algunas coincidencias de texto. Eso excedía la evidencia del sondeo regex. Ahora ambos caminos devuelven `UNKNOWN`/`INSUFFICIENT_EVIDENCE`, y el detalle explica la limitación. Las etiquetas antiguas guardadas se señalan como históricas y no validadas.
- **Atribución de OSV:** las vulnerabilidades ya se enlazan con el manifiesto/lockfile informado por OSV, cuando la ruta está dentro del checkout. Si no hay una ruta segura no se inventa una.
- **Inventario web:** el nombre de Lite ahora indica “PR diff” y avisa que no es el motor local completo. Zizmor aparece como herramienta opcional detectable y se ejecuta solo cuando existen definiciones CI rastreadas. La guía web aclara que instalar Bandit o ShellCheck no significa que el pipeline activo los haya ejecutado.

## Prioridad recomendada

### P0 — Cerrar la brecha entre inventario y ejecución

1. La web ya ofrece **Lite / diff del PR**, **motor local completo** y **Sentinel Cloud Pulse**. Mantener la disponibilidad local conectada al preflight y conservar el modo seleccionado en cada expediente; revisar la ruta con los motores local y Cloud antes de promocionar el flujo.
2. Conectar Bandit y ShellCheck al pipeline v1 o retirarlos del inventario activo hasta hacerlo. Añadir eligibilidad por lenguaje, motivo de ruta, versión, estado y denominador/cobertura real. Bandit es seguridad Python; ShellCheck debe clasificarse como lint/endurecimiento.
3. Hacer que el panel “Herramientas” diferencie `instalada`, `disponible`, `seleccionada`, `ejecutada`, `parcial` y `falló` por ejecución. El inventario de host no es cobertura del PR.
4. Mantener la calibración de confianza trazable: hoy `high/medium` significa conteo de autoridades, no probabilidad. No presentarlo como puntaje probabilístico.

### P1 — Completar huecos restantes

1. **Secretos históricos: evaluar Gitleaks.** Trivy ya revisa secretos presentes en el árbol, pero eso no cubre los parches de commits antiguos. Gitleaks puede recorrer historial Git y emitir JSON/SARIF; el adaptador tendría que forzar redacción, nunca persistir el secreto hallado y permitir baseline/fingerprints. Su README actual indica que el proyecto está completo y que nuevas funciones no son su foco, así que revisar mantenimiento y releases antes de adoptarlo como dependencia central. [README de Gitleaks](https://github.com/gitleaks/gitleaks).
2. **Trivy licencias, como módulo separado.** Trivy puede escanear licencias, pero la opción no está en la configuración actual. Agregarla solo si Sentinel distingue cumplimiento/licencia de vulnerabilidad y conserva el resultado como una categoría distinta. [Escáneres de filesystem de Trivy](https://trivy.dev/docs/dev/target/filesystem/).

### P2 — Bot de investigación y seguimiento

Construir primero un asistente **evidence-first** que prepare el expediente, no un bot que decida por severidad. Por candidato, debería:

- explicar qué regla y autoridad generaron cada señal;
- mostrar fuente, transformación, sink, controles y evidencia cruda, con enlace al SHA y líneas;
- proponer preguntas y pasos de verificación; registrar qué evidencia falta;
- deduplicar entre escaneos con fingerprint estable, conservar cambios entre commits, reaperturas, estados y responsable;
- redactar un comentario o reporte como borrador para aprobación humana, sin confirmar, descartar, publicar ni autorizar merges por sí solo.

Si más adelante se añade un modelo, que sea opcional y separado del veredicto determinista. Toda afirmación debe apuntar a evidencia citada; una respuesta sin evidencia queda como hipótesis. Medirlo con un corpus adjudicado y tasas de falsos positivos/negativos antes de anunciar mejoras. Ninguna combinación estática permite prometer “un mes de trabajo de un senior” sin una evaluación comparable y supervisión experta.

## Fuentes técnicas

- [CodeQL: consultas de flujo de datos con rutas](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/)
- [OSV-Scanner: manifiestos y lockfiles soportados](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)
- [Trivy: escaneo de secretos](https://trivy.dev/docs/dev/docs/scanner/secret/)
- [GitHub: SARIF para herramientas de análisis](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files)
