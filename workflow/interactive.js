'use strict';

const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');
const { execSync, execFileSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const cloudKeys = require('../lib/cloud-keys');
const liteScanner = require('../lib/lite-scanner');
const { runAuditV1 } = require('./pipeline-v1');
const { createTerminalProgress } = require('./terminal-progress');
const { loadConfig } = require('../lib/core');
const { resolveClient } = require('../adapters/hosted');

const ANSI = process.env.NO_COLOR == null && process.stdout.isTTY;
const paint = (code, text) => ANSI ? `\u001b[${code}m${text}\u001b[0m` : text;
const title = (text) => paint('1;36', text);
const good = (text) => paint('32', text);
const warn = (text) => paint('33', text);
const bad = (text) => paint('31;1', text);
function safeTerminal(value) {
  return String(value == null ? '' : value)
    .replace(/\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g, '')
    .replace(/[\u0000-\u001f\u007f]/g, (char) => char === '\n' ? '\n' : ' ');
}
let cachedGitHubSession;

function checkGitHubSession() {
  if (cachedGitHubSession) return cachedGitHubSession;
  try {
    const out = execSync('gh auth status', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const match = out.match(/account\s+([\w\d_-]+)/i) || out.match(/Logged in to [^\s]+ account ([\w\d_-]+)/i);
    cachedGitHubSession = {
      authenticated: true,
      account: match ? match[1] : 'GitHub CLI active',
      method: 'gh_cli'
    };
    return cachedGitHubSession;
  } catch (_) {
    if (process.env.GITHUB_TOKEN || process.env.GH_TOKEN) {
      cachedGitHubSession = {
        authenticated: true,
        account: 'Environment Token',
        method: 'env_token'
      };
      return cachedGitHubSession;
    }
    cachedGitHubSession = { authenticated: false };
    return cachedGitHubSession;
  }
}

function detectCurrentRepo() {
  try {
    const url = execSync('git remote get-url origin', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    const m = url.match(/[:/]([\w\d_.-]+)\/([\w\d_.-]+?)(\.git)?$/);
    if (m) return `${m[1]}/${m[2]}`;
  } catch (_) {}
  return null;
}

function safeRepo(value) {
  return /^[\w.-]+\/[\w.-]+$/.test(value);
}

function runGit(args, options = {}) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options });
}

function severityNumber(value) {
  return ({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 })[String(value || '').toUpperCase()] || 1;
}

function renderFindings(io, findings) {
  if (!findings.length) {
    io.output.write(good('No se encontraron señales en el diff analizado.') + '\n');
    return;
  }
  findings.forEach((f, idx) => {
    const sev = String(f.severity || 'INFO').toUpperCase();
    const color = sev === 'CRITICAL' || sev === 'HIGH' ? bad : sev === 'MEDIUM' ? warn : paint.bind(null, '36');
    io.output.write(`\n${color(`${String(idx + 1).padStart(2, '0')}  ${sev}`)}  ${safeTerminal(f.title)}  (${safeTerminal(f.file)}:${f.line || 0})\n`);
    if (f.snippet) io.output.write(`    ${safeTerminal(f.snippet).split('\n').join('\n    ')}\n`);
  });
}

async function handlePRWorkflow(io) {
  io.output.write('\n' + title('SENTINEL AUDIT  /  ESCANEO DE PULL REQUESTS') + '\n');
  io.output.write(paint('90', '──────────────────────────────────────────────────────────') + '\n');

  // 1. Verificar sesión activa de GitHub
  const gh = checkGitHubSession();
  if (gh.authenticated) {
    io.output.write(`${good('GitHub')}  ${gh.account}  (${gh.method})\n`);
  } else {
    io.output.write(warn('No se detectó sesión activa de GitHub en la terminal.') + '\n');
    io.output.write('  1) Iniciar sesión con GitHub CLI (gh auth login)\n');
    io.output.write('  2) Ingresar GitHub Personal Access Token manualmente\n');
    io.output.write('  3) Continuar sin autenticación (solo repositorios públicos)\n');
    const authChoice = (await io.question('Selecciona [1-3] (default 3): ')).trim();
    if (authChoice === '1') {
      io.output.write('Lanzando gh auth login...\n');
      try {
        execSync('gh auth login -w', { stdio: 'inherit' });
      } catch (e) {
        io.output.write(`Error al iniciar sesión: ${e.message}\n`);
      }
    } else if (authChoice === '2') {
      const token = (await io.question('Ingresa GITHUB_TOKEN: ')).trim();
      if (token) process.env.GITHUB_TOKEN = token;
    }
  }

  // 2. Repositorio a auditar
  let repo = detectCurrentRepo();
  if (repo) io.output.write(`Repositorio detectado: ${paint('1', repo)}\n`);
  const repoInput = repo ? '' : (await io.question('Repositorio [owner/repo]: ')).trim();
  if (repoInput) repo = repoInput;
  if (!safeRepo(repo || '')) {
    io.output.write(warn('Indica un repositorio válido con formato owner/repo.') + '\n');
    repo = (await io.question('Repositorio [owner/repo]: ')).trim();
  }
  if (!safeRepo(repo || '')) { io.output.write(bad('Repositorio inválido.') + '\n'); return null; }

  // 3. Enumerar PRs abiertos
  io.output.write(`\nConsultando Pull Requests abiertos en ${repo}...\n`);
  let prList = [];
  try {
    const raw = execFileSync('gh', ['pr', 'list', '--repo', repo, '--json', 'number,title,author,headRefName', '--limit', '30'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    prList = JSON.parse(raw);
  } catch (err) {
    io.output.write(warn(`No se pudo enumerar vía GitHub CLI (${err.message}).`) + '\n');
  }

  if (prList.length > 0) {
    io.output.write(`\nPull Requests abiertos encontrados en ${repo}:\n`);
    prList.forEach(p => {
      const authorLogin = (p.author && p.author.login) || 'unknown';
      io.output.write(`  ${paint('1', `#${p.number}`.padEnd(6))} ${safeTerminal(p.title).slice(0, 68).padEnd(70)} @${safeTerminal(authorLogin)}  ${paint('90', safeTerminal(p.headRefName))}\n`);
    });
  } else {
    io.output.write('No se encontraron PRs abiertos automáticamente. Puedes especificar el número directamente.\n');
  }

  const prNumStr = (await io.question('\nIngresa el número de PR a escanear: ')).trim();
  const prNumber = /^\d+$/.test(prNumStr) ? Number(prNumStr) : NaN;
  if (!Number.isSafeInteger(prNumber) || prNumber <= 0) {
    io.output.write('Número de PR inválido.\n');
    return null;
  }

  // 4. Seleccionar motor de escaneo
  const keys = cloudKeys.listKeys();
  const hasCloudKey = keys.length > 0;
  const { tools, policies } = loadConfig();
  const hostedPolicyEnabled = !!(policies.hosted && policies.hosted.enabled);
  const hostedClientAvailable = !!resolveClient({ tools }, {});
  const hostedUrl = process.env.SENTINEL_CLOUD_URL || null;
  const cloudReady = hostedPolicyEnabled && hostedClientAvailable && !!hostedUrl && hasCloudKey;
  const cloudReasons = [];
  if (!hostedPolicyEnabled) cloudReasons.push('policies.hosted.enabled está desactivado');
  if (!hostedClientAvailable) cloudReasons.push('falta @sentinel/cloud-client');
  if (!hostedUrl) cloudReasons.push('falta SENTINEL_CLOUD_URL');
  if (!hasCloudKey) cloudReasons.push('no hay clave Cloud guardada');
  io.output.write('\nMotor de entrada para Sentinel Audit:\n');
  io.output.write('  1) Sentinel Audit Lite local sobre el diff y especialistas justificados\n');
  io.output.write(cloudReady
    ? `  2) Sentinel Cloud Pulse; enviará el checkout fijado a Sentinel Cloud y ejecutará especialistas (${keys.length} clave(s))\n`
    : `  2) Sentinel Cloud Pulse no disponible: ${cloudReasons.join('; ')}\n`);
  const engineChoice = (await io.question('Selecciona [1/2] (default 1): ')).trim() || '1';
  if (engineChoice !== '1' && engineChoice !== '2') { io.output.write('Selección inválida.\n'); return null; }
  if (engineChoice === '2' && !cloudReady) {
    io.output.write(warn(`No se inició el Pulso: ${cloudReasons.join('; ')}.`) + '\n');
    return null;
  }
  let selectedCloudKey = null;
  if (engineChoice === '2') {
    if (keys.length === 1) selectedCloudKey = cloudKeys.getKey(keys[0].index);
    else {
      io.output.write('\nClaves Cloud disponibles (censuradas):\n');
      for (const key of keys) io.output.write(`  ${key.index}) ${key.name}  ${key.maskedToken}\n`);
      const index = Number((await io.question(`Selecciona [1-${keys.length}]: `)).trim());
      selectedCloudKey = Number.isInteger(index) ? cloudKeys.getKey(index) : null;
      if (!selectedCloudKey) { io.output.write('Selección de clave inválida.\n'); return null; }
    }
  }

  // 5. Obtener Diff y Ejecutar Escaneo
  io.output.write(`\nDescargando diff de PR #${prNumber} de ${repo}...\n`);
  let diff = '';
  try {
    diff = execFileSync('gh', ['pr', 'diff', String(prNumber), '--repo', repo], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    io.output.write(`Error al obtener diff de GitHub: ${err.message}\n`);
    return null;
  }

  io.output.write(`Diff obtenido (${Buffer.byteLength(diff, 'utf8')} bytes). Ejecutando señal Lite y pipeline de Sentinel Audit...\n`);
  const authorInfo = prList.find(p => p.number === prNumber)?.author?.login || 'unknown';
  const liteResult = liteScanner.auditPRDiff(diff, { repo, prNumber, author: authorInfo });
  const progress = createTerminalProgress({ stream: io.output });
  let auditResult = null;
  let checkout = null;
  let executionError = null;
  try {
    const prMeta = JSON.parse(execFileSync('gh', ['pr', 'view', String(prNumber), '--repo', repo, '--json', 'headRefOid,title,author,url'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
    if (!/^[a-f0-9]{40}$/i.test(prMeta.headRefOid || '')) throw new Error('GitHub no devolvió un SHA completo del head del PR.');
    checkout = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-pr-'));
    const clonePath = path.join(checkout, 'source');
    runGit(['clone', '--quiet', '--no-checkout', `https://github.com/${repo}.git`, clonePath]);
    runGit(['-C', clonePath, 'fetch', '--quiet', '--depth=1', 'origin', `refs/pull/${prNumber}/head`]);
    runGit(['-C', clonePath, 'checkout', '--quiet', '--detach', prMeta.headRefOid]);
    const seedFindings = liteResult.findings.map((f) => ({
      type: f.ruleId || f.rule || f.title || 'lite_signal', title: f.title, description: f.description,
      message: f.title, snippet: typeof f.snippet === 'string' ? f.snippet : null,
      file: f.file, line: Number.isInteger(f.line) && f.line > 0 ? f.line : null,
      severity: severityNumber(f.severity), evidence: [f.ruleId || f.rule || f.title].filter(Boolean),
    }));
    auditResult = await runAuditV1(clonePath, {
      name: `${repo.replace('/', '-')}-pr-${prNumber}`, commit: prMeta.headRefOid,
      ...(engineChoice === '1'
        ? { seedFindings, seedEngine: 'Sentinel Audit Lite PR diff' }
        : { provider: 'cloud', apiToken: selectedCloudKey.token, apiUrl: hostedUrl }),
      routing: 'file',
      onProgress: (event) => progress.update(event),
    });
  } catch (err) {
    executionError = err;
    progress.update({ stage: 'IDENTITY', state: 'FAILED', detail: `No se pudo fijar el PR: ${err.message}` });
    for (const stage of ['ENGINE', 'ROUTING', 'SPECIALISTS', 'CORRELATION', 'TRIAGE']) progress.update({ stage, state: 'NOT_RUN', detail: 'falló la obtención del checkout fijado' });
  } finally {
    progress.finish();
    if (checkout) { try { fs.rmSync(checkout, { recursive: true, force: true }); } catch (_) {} }
  }
  const result = liteResult;

  // 6. Mostrar resultados
  io.output.write('\n' + paint('1;36', '══════════════════════════════════════════════════════════') + '\n');
  io.output.write(title(`RESULTADO DEL ESCANEO: PR #${prNumber} (${repo})`) + '\n');
  const verdictColor = result.verdict === 'BLOCK' ? bad : result.verdict === 'REVIEW' ? warn : good;
  io.output.write(`VEREDICTO LITE:  ${verdictColor(result.verdict)}  |  RIESGO: ${paint('1;33', `${result.riskScore}/100`)}\n`);
  io.output.write(`HALLAZGOS LITE:  CRITICAL: ${bad(result.counts.critical)} | HIGH: ${warn(result.counts.high)} | MEDIUM: ${paint('36', result.counts.medium)} | LOW: ${result.counts.low}\n`);
  io.output.write(paint('1;36', '══════════════════════════════════════════════════════════') + '\n');

  if (result.findings.length > 0) {
    renderFindings(io, result.findings);
  } else {
    io.output.write(`  ${good('Sin hallazgos sospechosos ni credenciales expuestas.')}\n`);
  }

  if (auditResult) {
    const verdict = auditResult.expediente.auditVerdict || {};
    io.output.write('\n' + title('RESULTADO SENTINEL AUDIT') + '\n');
    io.output.write(`Veredicto: ${verdict.verdict || 'INCOMPLETO'} | estado: ${verdict.analysisState || 'desconocido'}\n`);
    io.output.write(`Ejecución: ${auditResult.executionDir}\n`);
    io.output.write(`Candidatos correlacionados: ${(auditResult.expediente.candidates || []).length}\n`);
    const engineResult = auditResult.expediente.tools && auditResult.expediente.tools.sentinel;
    io.output.write(`Motor de entrada: ${engineChoice === '2' ? 'Sentinel Cloud Pulse' : 'Sentinel Audit Lite diff'}; estado ${engineResult && engineResult.status || 'UNKNOWN'}; ${(engineResult && engineResult.findingCount) || 0} señales normalizadas\n`);
    for (const finding of (engineResult && engineResult.findings || [])) {
      io.output.write(`  ${safeTerminal(finding.category || 'signal')}  ${safeTerminal(finding.rule || 'Señal')}  ${finding.file ? `${safeTerminal(path.relative(auditResult.expediente.repository, finding.file))}${finding.line ? `:${finding.line}` : ''}` : '(sin archivo localizado)'}\n`);
      if (finding.detail) io.output.write(`    Evidencia: ${safeTerminal(finding.detail)}\n`);
    }
    const jobs = auditResult.expediente.specialistJobs || [];
    io.output.write('Analizadores de Audit:\n');
    if (!jobs.length) io.output.write('  No se programaron: ninguna señal del diff se pudo enrutar a un archivo elegible.\n');
    else for (const job of jobs) io.output.write(`  ${safeTerminal(job.tool)}: ${safeTerminal(job.outcome || job.status || job.state)}; ${job.findingCount || 0} señales${job.error ? ` — ${safeTerminal(job.error)}` : ''}\n`);
    const specialistResults = Object.entries(auditResult.expediente.tools || {}).filter(([tool]) => tool !== 'sentinel');
    for (const [tool, toolResult] of specialistResults) {
      io.output.write(`  ${safeTerminal(tool)}: ${safeTerminal(toolResult.status || 'UNKNOWN')}; ${toolResult.findingCount || 0} hallazgos${toolResult.error ? ` — ${safeTerminal(toolResult.error)}` : ''}\n`);
      for (const finding of (toolResult.findings || [])) {
        io.output.write(`    ${safeTerminal(finding.level || finding.kind || 'SIGNAL')}  ${safeTerminal(finding.rule || finding.detail || 'Hallazgo')}  ${safeTerminal(finding.file || '')}${finding.line ? `:${finding.line}` : ''}\n`);
      }
    }
    for (const candidate of (auditResult.expediente.candidates || [])) {
      io.output.write(`  ${safeTerminal(candidate.priority || candidate.severity || 'REVIEW')}  ${safeTerminal(candidate.title || candidate.rule || candidate.category || 'Candidato correlacionado')}\n`);
    }
    const notRun = Object.entries(auditResult.expediente.stages || {}).filter(([, stage]) => ['NOT_RUN', 'INCOMPLETE', 'FAILED'].includes(stage.state));
    if (notRun.length) {
      io.output.write(warn('Etapas incompletas o detenidas:') + '\n');
      for (const [stage, state] of notRun) io.output.write(`  ${stage}: ${safeTerminal(typeof state.detail === 'string' ? state.detail : JSON.stringify(state.detail || state.state))}\n`);
    }
  } else if (executionError) {
    io.output.write(warn(`Pipeline especializado no iniciado: ${executionError.message}`) + '\n');
  }

  // 7. Acciones post-escaneo
  while (true) {
    io.output.write('\n¿Qué deseas hacer ahora?\n');
    io.output.write('  1) Continuar / Terminar\n');
    io.output.write('  2) Volver a escanear otro PR\n');
    io.output.write('  3) Descargar reporte completo en Markdown (.md) en Descargas\n');
    const postChoice = (await io.question('Selecciona [1-3]: ')).trim();

    if (postChoice === '3') {
      const exported = liteScanner.exportToMarkdown(result);
      io.output.write(`\n${good('Reporte descargado:')} ${exported.fullPath} (${exported.bytes} bytes)\n`);
    } else if (postChoice === '2') {
      return handlePRWorkflow(io);
    } else {
      break;
    }
  }

  return null;
}

async function handleKeysWorkflow(io) {
  while (true) {
    io.output.write('\n──────────────────────────────────────────────────────────\n');
    io.output.write(title('GESTIÓN DE CLAVES DE SENTINEL CLOUD') + '\n');
    io.output.write('──────────────────────────────────────────────────────────\n');
    
    const keys = cloudKeys.listKeys();
    if (keys.length === 0) {
      io.output.write('No hay claves de Sentinel Cloud registradas en esta máquina.\n');
    } else {
      io.output.write('Claves almacenadas en la máquina (censuradas):\n');
      keys.forEach(k => {
        io.output.write(`  [${k.index}] ${k.name.padEnd(22)}: ${k.maskedToken} (Añadida: ${k.addedAt ? k.addedAt.slice(0, 10) : 'N/A'})\n`);
      });
    }

    io.output.write('\nOpciones:\n');
    io.output.write('  1) Añadir nueva clave Cloud\n');
    io.output.write('  2) Revocar / Eliminar clave de la máquina\n');
    io.output.write('  3) Volver al menú principal\n');

    const choice = (await io.question('Selecciona [1-3]: ')).trim();
    if (choice === '1') {
      const token = (await io.question('\nPega la clave de Sentinel Cloud: ')).trim();
      if (!token) {
        io.output.write('Operación cancelada. Clave vacía.\n');
        continue;
      }
      const name = (await io.question('Nombre identificador opcional (ej: Clave Producción): ')).trim();
      try {
        const added = cloudKeys.addKey(token, name);
        io.output.write(`${good('Clave guardada:')} "${added.name}" ${added.maskedToken}\n`);
      } catch (err) {
        io.output.write(`${bad('Error al guardar clave:')} ${err.message}\n`);
      }
    } else if (choice === '2') {
      if (keys.length === 0) {
        io.output.write('No hay claves para revocar.\n');
        continue;
      }
      const idxStr = (await io.question(`Número de clave a revocar [1-${keys.length}]: `)).trim();
      const idx = parseInt(idxStr, 10);
      if (isNaN(idx) || idx < 1 || idx > keys.length) {
        io.output.write('Selección inválida.\n');
        continue;
      }
      io.output.write('\n' + warn('AVISO DE REVOCACIÓN:') + '\n');
      io.output.write('  Revocar una clave desde este menú SOLO la elimina de tu máquina local.\n');
      io.output.write('  Si deseas invalidarla de forma permanente, debes eliminarla desde la consola web de Sentinel Cloud.\n');
      const confirm = (await io.question(`¿Seguro que deseas eliminar la Clave ${idx} de este equipo? [y/N]: `)).trim().toLowerCase();
      if (confirm === 'y' || confirm === 'yes') {
        try {
          const res = cloudKeys.revokeKey(idx);
          io.output.write(`${good(res.removed.name)} eliminada de esta máquina.\n`);
        } catch (err) {
          io.output.write(`Error: ${err.message}\n`);
        }
      }
    } else {
      break;
    }
  }
}

async function interactiveArgs(io) {
  const ownsInterface = !io;
  io = io || readline.createInterface({ input: stdin, output: stdout });
  try {
    io.output.write('\n' + paint('1;36', '███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗') + '\n');
    io.output.write(paint('1;36', '██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║') + '\n');
    io.output.write(paint('1;36', '███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║') + '\n');
    io.output.write(paint('1;36', '╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║') + '\n');
    io.output.write(paint('1;36', '███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗') + '\n');
    io.output.write(paint('1;36', '╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝') + '\n');
    io.output.write(paint('1;37', '                         SENTINEL AUDIT') + '\n');
    io.output.write(paint('90', '                    SECURITY AUDIT ORCHESTRATOR') + '\n');
    const github = checkGitHubSession();
    io.output.write(`GitHub: ${github.authenticated ? good(github.account) + ` (${github.method})` : warn('sin sesión detectada')}\n`);
    io.output.write(paint('90', '──────────────────────────────────────────────────────────') + '\n');

    io.output.write('Selecciona una opción:\n');
    io.output.write('  1) Enumerar y analizar Pull Requests\n');
    io.output.write('  2) Gestionar claves de Sentinel Cloud\n');
    io.output.write('  3) Diagnóstico de motores y herramientas\n');
    io.output.write('  4) Auditar un commit fijado\n');
    io.output.write('  5) Preflight de repositorio fijado\n');
    io.output.write('  6) Renderizar un reporte existente\n');
    io.output.write('  7) Leer aviso de responsabilidad\n');
    io.output.write('  8) Salir\n');

    const choice = (await io.question('\nSelecciona [1-8]: ')).trim();

    if (choice === '1') {
      await handlePRWorkflow(io);
      return null;
    }
    if (choice === '2') {
      await handleKeysWorkflow(io);
      return null;
    }
    if (choice === '3') return ['doctor'];
    if (choice === '7') {
      io.output.write(`\n${cloudKeys.DISCLAIMER_TEXT}\n`);
      return interactiveArgs(io);
    }
    if (choice === '8') return null;

    if (choice === '4' || choice === '5') {
      const repo = (await io.question('Ruta del repositorio: ')).trim();
      if (!repo) throw new Error('Se requiere la ruta del repositorio');
      const commit = (await io.question('SHA completo de 40 caracteres: ')).trim();
      if (!/^[a-f0-9]{40}$/i.test(commit)) throw new Error('Ingresa un SHA válido de 40 caracteres');
      if (choice === '5') return ['preflight', repo, '--commit', commit];
      const routing = (await io.question('Alcance [file/directory/repo] (default: file): ')).trim() || 'file';
      if (!['file', 'directory', 'repo'].includes(routing)) {
        throw new Error('Alcance debe ser file, directory o repo');
      }
      const confirm = (await io.question(`¿Ejecutar analizadores en ${repo} @ ${commit}? [y/N]: `)).trim().toLowerCase();
      if (confirm !== 'y' && confirm !== 'yes') return null;
      return ['run', repo, '--commit', commit, '--routing', routing];
    }
    if (choice === '6') {
      const execDir = (await io.question('Directorio de ejecución: ')).trim();
      if (!execDir) throw new Error('Se requiere el directorio de ejecución');
      return ['report', execDir];
    }

    throw new Error('Opción no reconocida');
  } finally {
    if (ownsInterface) io.close();
  }
}

module.exports = {
  interactiveArgs,
  checkGitHubSession,
  handlePRWorkflow,
  handleKeysWorkflow,
  safeTerminal
};
