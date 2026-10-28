'use strict';

const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');
const { execSync, execFileSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const cloudKeys = require('../lib/cloud-keys');
const sessionLogs = require('../lib/session-logs');
const liteScanner = require('../lib/lite-scanner');
const { runAuditV1 } = require('./pipeline-v1');
const { createTerminalProgress } = require('./terminal-progress');
const { loadConfig } = require('../lib/core');
const { resolveClient } = require('../adapters/hosted');
const { preflight } = require('./preflight');

const ANSI = process.env.NO_COLOR == null && process.stdout.isTTY;
const paint = (code, text) => ANSI ? `\u001b[${code}m${text}\u001b[0m` : text;
const title = (text) => paint('1;36', text);
const good = (text) => paint('32', text);
const warn = (text) => paint('33', text);
const bad = (text) => paint('31;1', text);
const accent = (text) => paint('1;35', text);
const BOX_WIDTH = 76;
const BOX_INNER = BOX_WIDTH - 4;
const stripAnsi = (value) => String(value).replace(/\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g, '');
function wrappedLines(value, max = BOX_INNER) {
  const words = safeTerminal(value).split(/\s+/);
  const rows = [];
  let row = '';
  for (const word of words) {
    if (word.length > max) {
      if (row) rows.push(row);
      for (let i = 0; i < word.length; i += max) rows.push(word.slice(i, i + max));
      row = '';
    } else if (!row) row = word;
    else if (row.length + word.length + 1 <= max) row += ` ${word}`;
    else { rows.push(row); row = word; }
  }
  if (row) rows.push(row);
  return rows.length ? rows : [''];
}
function panel(io, heading, content, color = '36') {
  const width = Math.min(BOX_WIDTH, Math.max(52, Number(process.stdout.columns) || BOX_WIDTH));
  const inner = width - 4;
  const top = `╭─ ${heading} ${'─'.repeat(Math.max(0, width - heading.length - 5))}╮`;
  io.output.write(paint(`1;${color}`, top) + '\n');
  for (const value of content) {
    const safeValue = safeTerminal(value);
    const rows = stripAnsi(safeValue).length <= inner ? [safeValue] : wrappedLines(stripAnsi(safeValue), inner);
    for (const row of rows) {
      const visibleLength = stripAnsi(row).length;
      io.output.write(`${paint(color, '│')} ${row}${' '.repeat(Math.max(0, inner - visibleLength))} ${paint(color, '│')}\n`);
    }
  }
  io.output.write(paint(`1;${color}`, `╰${'─'.repeat(width - 2)}╯`) + '\n');
}
function menuRow(number, label, description) {
  return `${String(number).padStart(2, '0')}  ${label.padEnd(18)} ${description}`;
}
function resultColor(verdict) {
  return verdict === 'BLOCK' || verdict === 'CANDIDATES_FOUND' ? bad : verdict === 'REVIEW' || verdict === 'PARTIAL_ANALYSIS' ? warn : good;
}
function safeTerminal(value) {
  return String(value == null ? '' : value)
    .replace(/\u001b(?:\[[0-?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\))/g, '')
    .replace(/[\u0000-\u001f\u007f]/g, (char) => char === '\n' ? '\n' : ' ')
    .replace(/\p{Extended_Pictographic}(?:\uFE0F|\u200D\p{Extended_Pictographic})*/gu, '');
}
let cachedGitHubSession;

function checkGitHubSession() {
  if (cachedGitHubSession) return cachedGitHubSession;
  try {
    const account = execFileSync('gh', ['api', 'user', '--jq', '.login'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    if (!/^[\w-]+$/.test(account)) throw new Error('GitHub CLI returned an invalid account name');
    cachedGitHubSession = {
      authenticated: true,
      account,
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

function listGitHubRepos(account) {
  if (!account || account === 'Environment Token') return [];
  const raw = execFileSync('gh', ['repo', 'list', account, '--json', 'nameWithOwner,description,isPrivate', '--limit', '100'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  return JSON.parse(raw);
}

async function chooseGitHubRepo(io, preferredRepo = null) {
  const gh = checkGitHubSession();
  let repos = [];
  try { repos = listGitHubRepos(gh.account); }
  catch (error) { io.output.write(warn(`No se pudo listar repositorios: ${safeTerminal(error.message)}`) + '\n'); }
  if (preferredRepo && !repos.some((item) => item.nameWithOwner === preferredRepo)) {
    repos.unshift({ nameWithOwner: preferredRepo, description: 'Repositorio detectado desde el directorio actual', isPrivate: false });
  }
  if (!repos.length) {
    io.output.write('No hay repositorios para seleccionar. Inicia sesión con gh o abre la CLI desde un repositorio GitHub.\n');
    return null;
  }
  panel(io, `REPOSITORIOS DE ${gh.account}`, repos.map((repo, index) => {
    const visibility = repo.isPrivate ? 'PRIVADO' : 'PUBLICO';
    return `${String(index + 1).padStart(2, '0')}  ${safeTerminal(repo.nameWithOwner).padEnd(38)} ${visibility}`;
  }).concat(`${paint('1;33', '00')}  Volver`), '36');
  const answer = (await io.question(`Selecciona [0-${repos.length}] (Enter = ${preferredRepo ? 'repositorio actual' : 'volver'}): `)).trim();
  if (!answer && preferredRepo) return repos.find((repo) => repo.nameWithOwner === preferredRepo) || repos[0];
  if (!/^\d+$/.test(answer)) return null;
  const index = Number(answer);
  return index > 0 && index <= repos.length ? repos[index - 1] : null;
}

async function chooseCommit(io, repo) {
  let commits;
  try {
    commits = JSON.parse(execFileSync('gh', ['api', `repos/${repo}/commits?per_page=12`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  } catch (error) {
    io.output.write(warn(`No se pudieron enumerar commits de ${repo}: ${safeTerminal(error.message)}`) + '\n');
    return null;
  }
  if (!Array.isArray(commits) || !commits.length) {
    io.output.write('No hay commits disponibles para seleccionar.\n');
    return null;
  }
  panel(io, `COMMITS RECIENTES · ${repo}`, commits.map((item, index) => {
    const sha = String(item.sha || '');
    const subject = String(item.commit && item.commit.message || '').split(/\r?\n/)[0];
    const date = item.commit && item.commit.author && item.commit.author.date || '';
    return `${String(index + 1).padStart(2, '0')}  ${sha.slice(0, 10)}  ${safeTerminal(date).slice(0, 10)}  ${safeTerminal(subject).slice(0, 46)}`;
  }).concat(`${paint('1;33', '00')}  Volver`), '36');
  const answer = (await io.question(`Selecciona commit [0-${commits.length}]: `)).trim();
  if (!/^\d+$/.test(answer)) return null;
  const index = Number(answer);
  return index > 0 && index <= commits.length ? commits[index - 1].sha : null;
}

async function clonePinnedCommit(repo, commit) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-pinned-'));
  const source = path.join(root, 'source');
  try {
    runGit(['clone', '--quiet', '--no-checkout', '--filter=blob:none', '--depth=1', `https://github.com/${repo}.git`, source]);
    runGit(['-C', source, 'fetch', '--quiet', '--depth=1', 'origin', commit]);
    runGit(['-C', source, 'checkout', '--quiet', '--detach', commit]);
    return { root, source };
  } catch (error) {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_) {}
    throw error;
  }
}

async function handlePinnedWorkflow(io, mode) {
  const preferredRepo = detectCurrentRepo();
  const selectedRepo = await chooseGitHubRepo(io, preferredRepo);
  if (!selectedRepo) { io.output.write('Volviendo al menú principal.\n'); return; }
  const repo = selectedRepo.nameWithOwner;
  const commit = await chooseCommit(io, repo);
  if (!commit) { io.output.write('Operación cancelada; no se eligió commit.\n'); return; }
  let checkout;
  try {
    io.output.write(`\nFijando ${repo} @ ${commit.slice(0, 12)} en un checkout temporal...\n`);
    checkout = await clonePinnedCommit(repo, commit);
    if (mode === 'preflight') {
      const result = preflight(checkout.source, { commit });
      io.output.write(`\n${title('PREFLIGHT SENTINEL AUDIT')}\n`);
      io.output.write(`Repositorio: ${repo}\nCommit: ${commit}\nVeredicto: ${result.verdict}\n`);
      for (const reason of (result.reasons || [])) io.output.write(`  Motivo: ${safeTerminal(reason)}\n`);
      for (const limit of (result.limits || [])) io.output.write(`  Límite: ${safeTerminal(limit)}\n`);
      io.output.write(`Motores disponibles: ${Object.entries(result.health || {}).filter(([, item]) => item && item.available).map(([name]) => name).join(', ') || 'ninguno'}\n`);
      return;
    }
    io.output.write('\nAlcance de especialistas:\n  1) Archivos señalados\n  2) Directorios señalados\n  3) Repositorio completo\n  0) Cancelar\n');
    const scope = (await io.question('Selecciona [0-3] (Enter = archivos señalados): ')).trim() || '1';
    if (!['1', '2', '3'].includes(scope)) { io.output.write('Auditoría cancelada.\n'); return; }
    const routing = ({ '1': 'file', '2': 'directory', '3': 'repo' })[scope];
    const progress = createTerminalProgress({ stream: io.output });
    let result;
    try { result = await runAuditV1(checkout.source, { name: repo.replace('/', '-'), commit, routing, onProgress: (event) => progress.update(event) }); }
    finally { progress.finish(); }
    const verdict = result.expediente.auditVerdict || {};
    io.output.write(`\n${title('RESULTADO SENTINEL AUDIT')}\n`);
    io.output.write(`Repositorio: ${repo}\nCommit: ${commit}\nVeredicto: ${verdict.verdict || 'INCOMPLETO'} (${verdict.analysisState || 'desconocido'})\n`);
    io.output.write(`Candidatos: ${(result.expediente.candidates || []).length}\nEjecución y evidencia: ${result.executionDir}\n`);
  } catch (error) {
    io.output.write(bad(`La operación no se completó: ${safeTerminal(error.message)}`) + '\n');
  } finally {
    if (checkout && checkout.root) { try { fs.rmSync(checkout.root, { recursive: true, force: true }); } catch (_) {} }
  }
}

function renderFindings(io, findings) {
  if (!findings.length) {
    panel(io, 'RESULTADOS LITE', [good('No se encontraron señales en el diff analizado.')], '32');
    return;
  }
  const visible = findings.slice(0, 8);
  for (let idx = 0; idx < visible.length; idx++) {
    const f = visible[idx];
    const sev = String(f.severity || 'INFO').toUpperCase();
    const color = sev === 'CRITICAL' || sev === 'HIGH' ? '31' : sev === 'MEDIUM' ? '33' : '36';
    const rows = [
      `${paint(`1;${color}`, `${String(idx + 1).padStart(2, '0')}  ${sev}`)}  ${safeTerminal(f.title || 'Señal de seguridad')}`,
      `UBICACION  ${safeTerminal(f.file || 'archivo no especificado')}${f.line ? `:${f.line}` : ''}`,
    ];
    if (f.snippet) rows.push(`EVIDENCIA  ${safeTerminal(f.snippet).replace(/\s+/g, ' ').slice(0, 220)}`);
    panel(io, `HALLAZGO ${String(idx + 1).padStart(2, '0')}`, rows, color);
  }
  if (findings.length > visible.length) io.output.write(paint('90', `Se muestran ${visible.length} de ${findings.length}; el reporte local contiene la evidencia completa.\n`));
}

async function handlePRWorkflow(io) {
  panel(io, 'SENTINEL AUDIT  /  REVISION DE PULL REQUESTS', ['Inspección del diff, análisis complementario y evidencia correlacionada.'], '36');

  // 1. Verificar sesión activa de GitHub
  const gh = checkGitHubSession();
  if (gh.authenticated) {
    panel(io, 'CUENTA GITHUB', [`CUENTA  ${good(gh.account)}`, `SESION  ${gh.method}`], '32');
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
  if (!repo) {
    const selected = await chooseGitHubRepo(io);
    repo = selected && selected.nameWithOwner;
  }
  if (!repo) { io.output.write('Volviendo al menú principal.\n'); return null; }
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

  let prNumber;
  if (prList.length > 0) {
    const choices = [];
    prList.forEach((pr, index) => {
      const authorLogin = (pr.author && pr.author.login) || 'desconocido';
      choices.push(`${String(index + 1).padStart(2, '0')}  #${String(pr.number).padEnd(5)} ${safeTerminal(pr.title).slice(0, 48)}`);
      choices.push(`    @${safeTerminal(authorLogin)} · ${safeTerminal(pr.headRefName)}`);
    });
    panel(io, `PULL REQUESTS ABIERTAS  /  ${repo}`, choices.concat('00  Volver al menu principal'), '36');
    const answer = (await io.question(`${accent('>')} Selecciona un Pull Request [1-${prList.length}] (0 = volver): `)).trim();
    if (!/^\d+$/.test(answer)) return null;
    const index = Number(answer);
    if (index < 1 || index > prList.length) { io.output.write('Volviendo al menú principal.\n'); return null; }
    prNumber = Number(prList[index - 1].number);
  } else {
    panel(io, 'PULL REQUESTS', ['No se pudieron enumerar solicitudes abiertas.', 'Si tienes el identificador del PR, puedes ingresarlo manualmente.', '00  Volver al menu principal'], '33');
    const answer = (await io.question(`${accent('>')} Numero del Pull Request (0 = volver): `)).trim();
    if (!/^\d+$/.test(answer) || Number(answer) <= 0) return null;
    prNumber = Number(answer);
  }
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
  panel(io, 'MOTOR DE ANALISIS', [
    '01  SENTINEL AUDIT LITE',
    '    Analisis local del diff y especialistas dirigidos.',
    cloudReady ? `02  SENTINEL CLOUD PULSE · ${keys.length} clave(s)` : '02  SENTINEL CLOUD PULSE · NO DISPONIBLE',
    ...(cloudReady ? ['    Motor alojado completo para el PR fijado.'] : [`    Requisito pendiente: ${cloudReasons.join('; ')}`]),
    '00  VOLVER AL MENU PRINCIPAL',
  ], '35');
  const engineChoice = (await io.question('Selecciona [0/1/2] (default 1): ')).trim() || '1';
  if (engineChoice === '0') return null;
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
      const rawIndex = (await io.question(`Selecciona [1-${keys.length}] (0 = volver): `)).trim();
      if (rawIndex === '0' || !rawIndex) return null;
      const index = Number(rawIndex);
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
  io.output.write('\n');
  const verdictColor = result.verdict === 'BLOCK' ? bad : result.verdict === 'REVIEW' ? warn : good;
  panel(io, `SCAN RESULT  /  PR #${prNumber} · ${repo}`, [
    `VEREDICTO LITE  ${verdictColor(result.verdict)}     RIESGO  ${paint('1;33', `${result.riskScore}/100`)}`,
    `CRITICO  ${bad(result.counts.critical)}   ALTO  ${warn(result.counts.high)}   MEDIO  ${paint('36', result.counts.medium)}   BAJO  ${result.counts.low}`,
    `HALLAZGOS  ${result.findings.length}     TAMANO DEL DIFF  ${Buffer.byteLength(diff, 'utf8')} bytes`,
  ], result.verdict === 'BLOCK' ? '31' : result.verdict === 'REVIEW' ? '33' : '32');

  if (result.findings.length > 0) {
    renderFindings(io, result.findings);
  } else {
    io.output.write(`  ${good('Sin hallazgos sospechosos ni credenciales expuestas.')}\n`);
  }

  if (auditResult) {
    const verdict = auditResult.expediente.auditVerdict || {};
    const engineResult = auditResult.expediente.tools && auditResult.expediente.tools.sentinel;
    const jobs = auditResult.expediente.specialistJobs || [];
    const specialistResults = Object.entries(auditResult.expediente.tools || {}).filter(([tool]) => tool !== 'sentinel');
    const totalSpecialistFindings = specialistResults.reduce((sum, [, item]) => sum + (item.findingCount || 0), 0);
    const gaps = [];
    const notRun = Object.entries(auditResult.expediente.stages || {}).filter(([, stage]) => ['NOT_RUN', 'INCOMPLETE', 'FAILED'].includes(stage.state));
    for (const [stage, state] of notRun) gaps.push(`${stage}: ${typeof state.detail === 'string' ? state.detail : JSON.stringify(state.detail || state.state)}`);
    if (jobs.length) for (const job of jobs) if (job.error) gaps.push(`${job.tool}: ${job.error}`);
    panel(io, 'SENTINEL AUDIT  /  CORROBORACION', [
      `VEREDICTO  ${resultColor(verdict.verdict)(verdict.verdict || 'INCOMPLETO')}  ·  ${verdict.analysisState || 'DESCONOCIDO'}`,
      `MOTOR DE ENTRADA  ${engineChoice === '2' ? 'Sentinel Cloud Pulse' : 'Sentinel Audit Lite'}  ·  ${engineResult && engineResult.status || 'DESCONOCIDO'}  ·  ${(engineResult && engineResult.findingCount) || 0} señales`,
      `ESPECIALISTAS  ${specialistResults.length} herramientas  ·  ${totalSpecialistFindings} hallazgos  ·  ${jobs.length} trabajos dirigidos`,
      ...specialistResults.slice(0, 4).map(([tool, item]) => `  ${tool}: ${item.status || 'DESCONOCIDO'} · ${item.findingCount || 0} hallazgos${item.error ? ` · ${item.error}` : ''}`),
      `CANDIDATOS CORRELACIONADOS  ${(auditResult.expediente.candidates || []).length}`,
      gaps.length ? `BRECHAS DE COBERTURA  ${gaps.slice(0, 2).map(safeTerminal).join(' | ')}` : (verdict.analysisState === 'COMPLETE' ? 'COBERTURA  Etapas completadas' : 'COBERTURA  Analisis parcial; revisar estados y requisitos del motor.'),
      `EXPEDIENTE COMPLETO  ${auditResult.executionDir}`,
    ], verdict.verdict === 'CANDIDATES_FOUND' ? '31' : verdict.analysisState === 'COMPLETE' ? '32' : '33');
  } else if (executionError) {
    io.output.write(warn(`Pipeline especializado no iniciado: ${executionError.message}`) + '\n');
  }

  // 7. Acciones post-escaneo
  while (true) {
    panel(io, 'SIGUIENTE ACCION', [
      '01  Regresar al menu principal',
      '02  Escanear otro Pull Request',
      '03  Guardar reporte detallado en Descargas',
    ], '36');
    const postChoice = (await io.question(`${accent('>')} Selecciona [1-3] (Enter = menu): `)).trim();

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
    const keys = cloudKeys.listKeys();
    panel(io, 'CLAVES SENTINEL CLOUD', keys.length
      ? keys.map((key) => `${String(key.index).padStart(2, '0')}  ${safeTerminal(key.name).padEnd(24)} ${key.maskedToken}  ·  ${key.addedAt ? key.addedAt.slice(0, 10) : 'sin fecha'}`)
      : ['No hay claves registradas en esta maquina.'], '35');
    panel(io, 'ACCIONES', ['01  Agregar una clave Cloud', '02  Eliminar una clave guardada localmente', '00  Volver al menu principal'], '36');

    const choice = (await io.question(`${accent('>')} Selecciona [0-2] (Enter = volver): `)).trim();
    if (!choice || choice === '0' || choice === '3') break;
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
      const idxStr = (await io.question(`Número de clave a revocar [1-${keys.length}] (0 = volver): `)).trim();
      if (!idxStr || idxStr === '0') continue;
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

function listSavedExecutions() {
  const root = path.resolve(__dirname, '..', 'out');
  const rows = [];
  if (!fs.existsSync(root)) return rows;
  for (const group of fs.readdirSync(root, { withFileTypes: true })) {
    if (!group.isDirectory()) continue;
    const groupPath = path.join(root, group.name);
    for (const run of fs.readdirSync(groupPath, { withFileTypes: true })) {
      if (!run.isDirectory()) continue;
      const executionDir = path.join(groupPath, run.name);
      const file = path.join(executionDir, 'expediente.json');
      if (!fs.existsSync(file)) continue;
      try {
        const data = JSON.parse(fs.readFileSync(file, 'utf8'));
        rows.push({ executionDir, name: data.name || group.name, commit: data.commit || 'unknown', verdict: data.auditVerdict && data.auditVerdict.verdict || 'UNKNOWN', startedAt: data.startedAt || '' });
      } catch (_) {}
    }
  }
  return rows.sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
}

async function chooseSavedExecution(io) {
  const rows = listSavedExecutions();
  if (!rows.length) {
    io.output.write('Todavía no hay ejecuciones guardadas para renderizar.\n');
    return null;
  }
  panel(io, 'EXPEDIENTES LOCALES', rows.slice(0, 30).map((row, index) =>
    `${String(index + 1).padStart(2, '0')}  ${safeTerminal(row.name).slice(0, 26).padEnd(26)}  ${safeTerminal(row.commit).slice(0, 10)}  ${safeTerminal(row.verdict)}`
  ).concat('00  Volver al menu principal'), '36');
  const answer = (await io.question(`Selecciona reporte [0-${Math.min(rows.length, 30)}]: `)).trim();
  if (!/^\d+$/.test(answer)) return null;
  const index = Number(answer);
  return index > 0 && index <= Math.min(rows.length, 30) ? rows[index - 1].executionDir : null;
}

async function interactiveArgs(io) {
  const ownsInterface = !io;
  io = io || readline.createInterface({ input: stdin, output: stdout });
  sessionLogs.beginSession();
  const restoreOutput = sessionLogs.captureStream(io.output);
  const restoreError = io.output === process.stderr ? () => {} : sessionLogs.captureStream(process.stderr);
  try {
   while (true) {
    const github = checkGitHubSession();
    panel(io, 'SENTINEL AUDIT  /  SECURITY WORKBENCH', [
      `Cuenta GitHub  ${github.authenticated ? good(github.account) : warn('sin sesion detectada')}  ${github.authenticated ? `(${github.method})` : ''}`,
      'Analisis local, auditoria especializada y evidencia verificable.',
      `CONSOLA WEB  http://127.0.0.1:${Number(process.env.SENTINEL_AUDIT_WEB_PORT) || 4317}  ·  iniciar con: sentinel-audit web`,
    ], '36');
    panel(io, 'OPERACIONES', [
      menuRow(1, 'PULL REQUESTS', 'Enumerar y analizar cambios propuestos'),
      menuRow(2, 'CLOUD KEYS', 'Administrar claves de Sentinel Cloud'),
      menuRow(3, 'DIAGNOSTICOS', 'Revisar motores y herramientas disponibles'),
      menuRow(4, 'AUDITAR COMMIT', 'Elegir repositorio y commit desde GitHub'),
      menuRow(5, 'PREFLIGHT', 'Comprobar cobertura antes de auditar'),
      menuRow(6, 'REPORTES', 'Abrir un expediente guardado'),
      menuRow(7, 'RESPONSABILIDAD', 'Leer alcance y limites del analisis'),
      menuRow(8, 'LOGS DE SESION', 'Consultar actividad de esta ejecucion'),
      menuRow(9, 'SALIR', 'Cerrar Sentinel Audit'),
    ], '35');

    const choice = (await io.question(`\n${accent('>')} Selecciona una operacion [1-9] (${paint('90', 'Enter = salir')}): `)).trim();
    if (!choice || choice === '0') return null;

    if (choice === '1') {
      await handlePRWorkflow(io);
      continue;
    }
    if (choice === '2') {
      await handleKeysWorkflow(io);
      continue;
    }
    if (choice === '3') return ['doctor'];
    if (choice === '7') {
      io.output.write(`\n${cloudKeys.DISCLAIMER_TEXT}\n`);
      continue;
    }
    if (choice === '8') {
      const entries = sessionLogs.getSessionLogs(40);
      panel(io, 'LOGS DE ESTA SESION', entries.length
        ? entries.map((entry) => `${entry.at.slice(11, 19)}  ${entry.text}`)
        : ['Todavia no hay actividad registrada.'].concat('00  Volver al menu principal'), '36');
      await io.question(`${accent('>')} Presiona Enter para volver al menu principal: `);
      continue;
    }
    if (choice === '9') return null;

    if (choice === '4' || choice === '5') {
      await handlePinnedWorkflow(io, choice === '5' ? 'preflight' : 'run');
      continue;
    }
    if (choice === '6') {
      const execDir = await chooseSavedExecution(io);
      if (!execDir) { io.output.write('Volviendo al menú principal.\n'); continue; }
      return ['report', execDir];
    }

    io.output.write(warn('Opción no reconocida; el menú sigue disponible.') + '\n');
   }
  } finally {
    sessionLogs.endSession();
    restoreOutput(); restoreError();
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
