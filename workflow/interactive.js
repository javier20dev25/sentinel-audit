'use strict';

const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');
const { execSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const cloudKeys = require('../lib/cloud-keys');
const liteScanner = require('../lib/lite-scanner');

function checkGitHubSession() {
  try {
    const out = execSync('gh auth status', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const match = out.match(/account\s+([\w\d_-]+)/i) || out.match(/Logged in to [^\s]+ account ([\w\d_-]+)/i);
    return {
      authenticated: true,
      account: match ? match[1] : 'GitHub CLI active',
      method: 'gh_cli'
    };
  } catch (_) {
    if (process.env.GITHUB_TOKEN || process.env.GH_TOKEN) {
      return {
        authenticated: true,
        account: 'Environment Token',
        method: 'env_token'
      };
    }
    return { authenticated: false };
  }
}

function detectCurrentRepo() {
  try {
    const url = execSync('git remote get-url origin', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    const m = url.match(/[:/]([\w\d_.-]+)\/([\w\d_.-]+?)(\.git)?$/);
    if (m) return `${m[1]}/${m[2]}`;
  } catch (_) {}
  return 'javier20dev25/Merx';
}

async function handlePRWorkflow(io) {
  io.output.write('\n──────────────────────────────────────────────────────────\n');
  io.output.write('🔍 SENTINEL AUDIT — ESCANEO DE PULL REQUESTS\n');
  io.output.write('──────────────────────────────────────────────────────────\n');

  // 1. Verificar sesión activa de GitHub
  const gh = checkGitHubSession();
  if (gh.authenticated) {
    io.output.write(`✓ Sesión activa de GitHub detectada: ${gh.account} (vía ${gh.method})\n`);
  } else {
    io.output.write('⚠ No se detectó sesión activa de GitHub en la terminal.\n');
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
  const defaultRepo = detectCurrentRepo();
  const repoInput = (await io.question(`\nRepositorio [owner/repo] (default: ${defaultRepo}): `)).trim();
  const repo = repoInput || defaultRepo;

  // 3. Enumerar PRs abiertos
  io.output.write(`\nConsultando Pull Requests abiertos en ${repo}...\n`);
  let prList = [];
  try {
    const cmd = `gh pr list --repo ${repo} --json number,title,author,headRefName --limit 15`;
    const raw = execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    prList = JSON.parse(raw);
  } catch (err) {
    io.output.write(`⚠ No se pudo enumerar vía gh (${err.message}).\n`);
  }

  if (prList.length > 0) {
    io.output.write(`\nPull Requests abiertos encontrados en ${repo}:\n`);
    prList.forEach(p => {
      const authorLogin = (p.author && p.author.login) || 'unknown';
      io.output.write(`  #${p.number.toString().padEnd(4)} | ${p.title.slice(0, 50).padEnd(52)} | por @${authorLogin} (${p.headRefName})\n`);
    });
  } else {
    io.output.write('No se encontraron PRs abiertos automáticamente. Puedes especificar el número directamente.\n');
  }

  const prNumStr = (await io.question('\nIngresa el número de PR a escanear: ')).trim();
  const prNumber = parseInt(prNumStr, 10);
  if (isNaN(prNumber) || prNumber <= 0) {
    io.output.write('Número de PR inválido.\n');
    return null;
  }

  // 4. Seleccionar motor de escaneo
  const keys = cloudKeys.listKeys();
  const hasCloudKey = keys.length > 0;

  io.output.write('\nSelecciona el motor de escaneo:\n');
  io.output.write('  1) Escáner Local (Motor Lite — SAST determinista offline)\n');
  if (hasCloudKey) {
    io.output.write(`  2) Usar Pulsos (Sentinel Cloud API) [${keys.length} clave(s) disponible(s)]\n`);
  } else {
    io.output.write('  2) [No disponible - Sin Cloud API Key configurada]\n');
  }

  const engineChoice = (await io.question('Selecciona [1 o 2]: ')).trim();
  let selectedKey = null;

  if (engineChoice === '2') {
    if (!hasCloudKey) {
      io.output.write('⚠ Opción no disponible. No hay claves de Sentinel Cloud en la máquina.\n');
      return null;
    }
    if (keys.length === 1) {
      selectedKey = cloudKeys.getKey(1);
      io.output.write(`Usando ${selectedKey.name} (${keys[0].maskedToken})\n`);
    } else {
      io.output.write('\nClaves de Sentinel Cloud disponibles en esta máquina:\n');
      keys.forEach(k => {
        io.output.write(`  ${k.index}) ${k.name.padEnd(20)} [${k.maskedToken}]\n`);
      });
      const keyChoice = parseInt((await io.question(`Selecciona clave [1-${keys.length}]: `)).trim(), 10);
      selectedKey = cloudKeys.getKey(keyChoice) || cloudKeys.getKey(1);
      io.output.write(`Seleccionada: ${selectedKey.name}\n`);
    }
  }

  // 5. Obtener Diff y Ejecutar Escaneo
  io.output.write(`\nDescargando diff de PR #${prNumber} de ${repo}...\n`);
  let diff = '';
  try {
    diff = execSync(`gh pr diff ${prNumber} --repo ${repo}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    io.output.write(`Error al obtener diff de GitHub: ${err.message}\n`);
    return null;
  }

  io.output.write(`Diff obtenido con éxito (${Buffer.byteLength(diff, 'utf8')} bytes). Analizando...\n`);
  const authorInfo = prList.find(p => p.number === prNumber)?.author?.login || 'unknown';
  const result = liteScanner.auditPRDiff(diff, { repo, prNumber, author: authorInfo });

  // 6. Mostrar resultados
  io.output.write('\n══════════════════════════════════════════════════════════\n');
  io.output.write(`RESULTADO DEL ESCANEO: PR #${prNumber} (${repo})\n`);
  io.output.write(`VEREDICTO:  [ ${result.verdict} ]  ·  RIESGO: ${result.riskScore}/100\n`);
  io.output.write(`HALLAZGOS:  CRITICAL: ${result.counts.critical} | HIGH: ${result.counts.high} | MEDIUM: ${result.counts.medium} | LOW: ${result.counts.low}\n`);
  io.output.write('══════════════════════════════════════════════════════════\n');

  if (result.findings.length > 0) {
    result.findings.slice(0, 10).forEach((f, idx) => {
      io.output.write(`  ${idx + 1}. [${f.severity}] ${f.title} (${f.file}:${f.line || 0})\n`);
      if (f.snippet) io.output.write(`     > ${f.snippet.replace(/\n/g, ' ').slice(0, 100)}\n`);
    });
    if (result.findings.length > 10) {
      io.output.write(`     ... y ${result.findings.length - 10} hallazgo(s) más.\n`);
    }
  } else {
    io.output.write('  ✓ Sin hallazgos sospechosos ni credenciales expuestas.\n');
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
      io.output.write(`\n✓ Reporte descargado exitosamente:\n  📄 ${exported.fullPath} (${exported.bytes} bytes)\n`);
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
    io.output.write('🔑 GESTIÓN DE CLAVES DE SENTINEL CLOUD\n');
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
        io.output.write(`✓ Clave "${added.name}" guardada exitosamente: ${added.maskedToken}\n`);
      } catch (err) {
        io.output.write(`⚠ Error al guardar clave: ${err.message}\n`);
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
      io.output.write('\n⚠ ADVERTENCIA DE REVOCACIÓN:\n');
      io.output.write('  Revocar una clave desde este menú SOLO la elimina de tu máquina local.\n');
      io.output.write('  Si deseas invalidarla de forma permanente, debes eliminarla desde la consola web de Sentinel Cloud.\n');
      const confirm = (await io.question(`¿Seguro que deseas eliminar la Clave ${idx} de este equipo? [y/N]: `)).trim().toLowerCase();
      if (confirm === 'y' || confirm === 'yes') {
        try {
          const res = cloudKeys.revokeKey(idx);
          io.output.write(`✓ ${res.removed.name} eliminada de la máquina.\n`);
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
    io.output.write('\n══════════════════════════════════════════════════════════\n');
    io.output.write('🛡️  SENTINEL AUDIT — Terminal Security Orchestrator\n');
    io.output.write('══════════════════════════════════════════════════════════\n');
    io.output.write(`⚖  ${cloudKeys.DISCLAIMER_TEXT}\n`);
    io.output.write('──────────────────────────────────────────────────────────\n');

    io.output.write('Selecciona una opción:\n');
    io.output.write('  1) 🔍 Enumerar y Escanear Pull Requests (Motor Lite / Pulsos)\n');
    io.output.write('  2) 🔑 Gestionar Claves de Sentinel Cloud\n');
    io.output.write('  3) 🩺 Diagnóstico y Verificación de Herramientas (Doctor)\n');
    io.output.write('  4) 🚀 Ejecutar auditoría sobre commit fijado\n');
    io.output.write('  5) 🔎 Preflight de repositorio fijado\n');
    io.output.write('  6) 📄 Renderizar reporte desde directorio previo\n');
    io.output.write('  7) 🚪 Salir\n');

    const choice = (await io.question('\nSelecciona [1-7]: ')).trim();

    if (choice === '1') {
      await handlePRWorkflow(io);
      return null;
    }
    if (choice === '2') {
      await handleKeysWorkflow(io);
      return null;
    }
    if (choice === '3') return ['doctor'];
    if (choice === '7') return null;

    if (choice === '4' || choice === '5') {
      const repo = (await io.question('Ruta del repositorio: ')).trim();
      if (!repo) throw new Error('Se requiere la ruta del repositorio');
      const commit = (await io.question('SHA completo de 40 caracteres: ')).trim();
      if (!/^[a-f0-9]{40}$/i.test(commit)) throw new Error('Ingresa un SHA válido de 40 caracteres');
      if (choice === '5') return ['preflight', repo, '--commit', commit];
      const routing = (await io.question('Alcance [file/directory/repo] (default: file): ')).trim() || 'file';
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
  handleKeysWorkflow
};
