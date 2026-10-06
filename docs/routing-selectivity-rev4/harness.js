'use strict';
// Brazos del experimento de routing selectivo de Semgrep.
//
//   A = escaneo por DIRECTORIO (mecanismo unscoped de adapters/index.js:189)
//   B = solo la shortlist promovida por Sentinel Cloud (produccion, Rev.2)
//   F = lista EXPLICITA de todos los archivos versionados, por lotes
//
// A sirve para comparar TIEMPO (1 proceso por config, igual que B y que Rev.2).
// F sirve como denominador de RECALL: es el unico brazo con universo de archivos
// conocido y completo, porque el recorrido por directorio de Semgrep salta
// test/ y build/ (medido: 0 de 93 en fastify, 0 de 19 en express) mientras que
// los archivos explicitos si se escanean. A no es superconjunto de B.
//
// Uso: node harness.js <repoDirName> <A|B|F>

const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');

const W = process.env.TEMP + '\\opencode\\cloud-calibration-5';
const CLONES = path.join(W, 'clones');
const OUT = path.join(W, 'ab');

const CONFIGS = ['p/security-audit', 'p/secrets'];   // config/tools.json : semgrep.configs
const PER_FILE_TIMEOUT_S = 900;                      // policies.budget.perToolMinutes.semgrep = 15
const OUTER_KILL_MS = 30 * 60 * 1000;
const MAX_SCAN_BYTES = 64 * 1024 * 1024;
const BATCH = Number(process.env.AB_BATCH || 150);    // solo F: evita el limite de linea de comandos

function args(cfg, targets) {
  return ['scan', '--config', cfg, '--json', '--quiet', '--metrics=off',
    '--disable-version-check', '--no-git-ignore', '--timeout', String(PER_FILE_TIMEOUT_S),
    '--exclude', 'node_modules', '--exclude', '.git', '--', ...targets];
}

function sampler(stopFile) {
  const ps = `$peak=0;$cpu=0.0;$n=0
while(-not (Test-Path '${stopFile}')){
  $p=Get-Process -Name semgrep,python,python3 -ErrorAction SilentlyContinue
  if($p){
    $ws=($p | Measure-Object -Property WorkingSet64 -Sum).Sum
    if($ws -gt $peak){$peak=$ws}
    $c=0.0; foreach($x in $p){ try{ $c+=$x.TotalProcessorTime.TotalSeconds }catch{} }
    if($c -gt $cpu){$cpu=$c}
  }
  Start-Sleep -Milliseconds 500
  $n++; if($n -gt 4000){break}
}
@{peakRssMB=[math]::Round($peak/1MB,1);cpuSec=[math]::Round($cpu,1);polls=$n} | ConvertTo-Json -Compress`;
  const p = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], { stdio: ['ignore', 'pipe', 'ignore'] });
  let buf = '';
  p.stdout.on('data', (d) => { buf += d; });
  return new Promise((res) => {
    p.on('close', () => { try { res(JSON.parse(buf.trim())); } catch { res({ peakRssMB: null, cpuSec: null }); } });
  });
}

function runSemgrep(cfg, root, targets) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const child = spawn('semgrep', args(cfg, targets), { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = []; let outBytes = 0; let overflow = false; let stderr = '';
    const kill = setTimeout(() => { overflow = true; child.kill(); }, OUTER_KILL_MS);
    child.stdout.on('data', (d) => { outBytes += d.length; if (outBytes <= MAX_SCAN_BYTES) out.push(d); });
    child.stderr.on('data', (d) => { if (stderr.length < 4000) stderr += d; });
    child.on('close', (code) => {
      clearTimeout(kill);
      const wallMs = Number((process.hrtime.bigint() - t0) / 1000000n);
      let j = null, parseError = null;
      try {
        const s = Buffer.concat(out).toString('utf8');
        const i = s.search(/[[{]/);
        if (i < 0) parseError = 'no-json'; else j = JSON.parse(s.slice(i));
      } catch (e) { parseError = String(e.message).slice(0, 200); }
      resolve({ config: cfg, exitCode: code, wallMs, stdoutBytes: outBytes, overflow, parseError, stderr: stderr.slice(0, 1200), json: j });
    });
  });
}

(async function main() {
  const repo = process.argv[2];
  const arm = process.argv[3];
  if (!repo || !['A', 'B', 'F'].includes(arm)) { console.error('uso: node harness.js <repoDirName> <A|B|F>'); process.exit(2); }

  const dest = path.join(OUT, repo + '__' + arm + '.json');
  if (fs.existsSync(dest) && !process.env.AB_FORCE) { console.log('SKIP ya existe ' + repo + '__' + arm); return; }

  const root = path.join(CLONES, repo);
  const exp = JSON.parse(fs.readFileSync(path.join(W, 'out', repo, 'expediente.json'), 'utf8'));

  let scopeKind, batches, rejectedPaths = [];
  if (arm === 'A') {
    scopeKind = 'whole-repo-directory-scan';
    batches = [[root]];
  } else if (arm === 'B') {
    const files = (exp.shortlist && exp.shortlist.files) || [];
    const abs = files.map((f) => path.join(root, f.split('/').join(path.sep))).filter((p) => fs.existsSync(p));
    scopeKind = 'cloud-promoted-shortlist';
    batches = [abs];
  } else {
    const tracked = execSync('git -C "' + root + '" ls-files -z', { maxBuffer: 1 << 28 })
      .toString('utf8').split('\0').filter(Boolean);
    // Semgrep aborta el lote ENTERO con "Invalid scanning root" si una ruta
    // contiene $ (medido: 64 archivos de svelte, p.ej. documentation/docs/02-runes/02-$state.md).
    // Se excluyen y se registran; ninguno estaba en la shortlist de Rev.2.
    const rejected = tracked.filter((f) => /\$/.test(f));
    const usable = tracked.filter((f) => !/\$/.test(f))
      .filter((f) => fs.existsSync(path.join(root, f.split('/').join(path.sep))));
    // Rutas RELATIVAS al repo: acortan el target a la mitad y evitan el limite de
    // 32k de la linea de comandos en Windows. Semgrep las resuelve contra cwd=root.
    scopeKind = 'all-tracked-files-explicit-batched-relative';
    batches = [];
    for (let i = 0; i < usable.length; i += BATCH) batches.push(usable.slice(i, i + BATCH));
    if (!batches.length) batches = [[]];
    rejectedPaths = rejected;
  }

  const commit = execSync('git -C "' + root + '" rev-parse HEAD').toString().trim();
  const tree = execSync('git -C "' + root + '" rev-parse "HEAD^{tree}"').toString().trim();
  const sgVer = execSync('semgrep --version').toString().trim().split('\n').pop().trim();

  const nTargets = batches.reduce((a, b) => a + b.length, 0);
  console.log('[' + repo + ' ' + arm + '] scope=' + scopeKind + ' batches=' + batches.length +
    ' targets=' + nTargets + ' semgrep=' + sgVer + ' commit=' + commit.slice(0, 12));
  if (!nTargets) { console.log('  sin targets, no se corre'); return; }

  const stopFile = path.join(OUT, repo + '__' + arm + '.stop');
  if (fs.existsSync(stopFile)) fs.unlinkSync(stopFile);
  const samP = sampler(stopFile);

  // Reanudable: cada corrida se guarda en parts/ y se omite si ya existe, para que
  // una muerte a mitad de camino no tire 20 minutos de trabajo.
  const partsDir = path.join(OUT, 'parts');
  if (!fs.existsSync(partsDir)) fs.mkdirSync(partsDir, { recursive: true });
  const FROM = Number(process.env.AB_FROM || 0);
  const TO = Number(process.env.AB_TO || batches.length);

  const perConfig = [];
  for (const cfg of CONFIGS) {
    for (let bi = 0; bi < batches.length; bi++) {
      const partFile = path.join(partsDir, repo + '__' + arm + '__' + cfg.replace(/[^a-z0-9]+/gi, '_') + '__' + bi + '.json');
      if (fs.existsSync(partFile) && !process.env.AB_FORCE) {
        const done = JSON.parse(fs.readFileSync(partFile, 'utf8'));
        perConfig.push(done.record);
        console.log('  ++ ' + cfg + ' lote ' + (bi + 1) + '/' + batches.length + ' ya estaba (scanned=' + done.record.filesScanned + ' findings=' + done.record.findings.length + ')');
        continue;
      }
      if (bi < FROM || bi >= TO) continue;
      console.log('  -> ' + cfg + ' lote ' + (bi + 1) + '/' + batches.length + ' (' + batches[bi].length + ' targets)');
      // Pausa entre procesos: en Windows el spawn rapido y repetido puede fallar con EAGAIN.
      await new Promise((r) => setTimeout(r, 700));
      let r;
      try {
        r = await runSemgrep(cfg, root, batches[bi]);
      } catch (e) {
        console.log('     EXCEPTION: ' + String(e && e.message).slice(0, 200));
        const rec = { config: cfg, batch: bi, batchSize: batches[bi].length, exitCode: -1,
          wallMs: 0, stdoutBytes: 0, overflow: false, parseError: 'spawn-failed:' + String(e && e.code),
          stderr: String(e && e.message).slice(0, 400), filesScanned: 0, scannedPaths: [], errors: [], findings: [] };
        fs.writeFileSync(partFile, JSON.stringify({ record: rec }, null, 2));
        perConfig.push(rec);
        continue;
      }
      const j = r.json || {};
      const scanned = (j.paths && j.paths.scanned) || [];
      const res = j.results || [];
      console.log('     exit=' + r.exitCode + ' wall=' + (r.wallMs / 1000).toFixed(1) + 's' +
        ' scanned=' + scanned.length + ' results=' + res.length + ' errors=' + ((j.errors || []).length) +
        (r.parseError ? ' PARSE_ERR=' + r.parseError : ''));
      if (r.exitCode !== 0) console.log('     NOTE: ' + JSON.stringify(j.errors).slice(0, 300));
      const rec = {
        config: cfg, batch: bi, batchSize: batches[bi].length,
        exitCode: r.exitCode, wallMs: r.wallMs, stdoutBytes: r.stdoutBytes,
        overflow: r.overflow, parseError: r.parseError, stderr: r.stderr,
        filesScanned: scanned.length,
        scannedPaths: scanned.map((p) => p.split('\\').join('/')),
        errors: j.errors || [],
        findings: res.map((x) => ({
          path: String(x.path || '').split('\\').join('/'),
          line: x.start ? x.start.line : null,
          endLine: x.end ? x.end.line : null,
          checkId: x.check_id,
          severity: x.extra && x.extra.metadata ? (x.extra.metadata.impact || x.extra.metadata.severity || null) : null,
          message: x.extra && x.extra.message ? String(x.extra.message).split('\n')[0].slice(0, 200) : '',
        })),
      };
      fs.writeFileSync(partFile, JSON.stringify({ record: rec }, null, 2));
      perConfig.push(rec);
    }
  }

  const expected = CONFIGS.length * batches.length;
  if (perConfig.length < expected) {
    fs.writeFileSync(stopFile, 'stop');
    await samP;
    try { fs.unlinkSync(stopFile); } catch (e) { /* best effort */ }
    console.log('  PARCIAL: ' + perConfig.length + '/' + expected + ' corridas. Reanuda con AB_FROM/AB_TO o sin ellos.');
    return;
  }
  fs.writeFileSync(stopFile, 'stop');
  const usage = await samP;
  try { fs.unlinkSync(stopFile); } catch (e) { /* best effort */ }

  const files = new Set(); const findings = [];
  for (const p of perConfig) for (const s of p.scannedPaths) files.add(s);
  for (const p of perConfig) findings.push(...p.findings);

  const record = {
    arm, scopeKind, repo, repoDir: root, commit, tree, semgrepVersion: sgVer,
    configs: CONFIGS, perFileTimeoutS: PER_FILE_TIMEOUT_S, batchSize: arm === 'F' ? BATCH : null,
    batches: batches.length, flags: ['scan', '--config <cfg>', '--json', '--quiet', '--metrics=off',
      '--disable-version-check', '--no-git-ignore', '--timeout 900', '--exclude node_modules',
      '--exclude .git', '--', '<targets>'],
    targetsUsed: nTargets,
    rejectedDollarPaths: rejectedPaths,
    filesScannedUnion: files.size, findingsTotal: findings.length,
    errorsTotal: perConfig.reduce((a, p) => a + p.errors.length, 0),
    wallMsTotal: perConfig.reduce((a, p) => a + p.wallMs, 0),
    wallMsPerRun: perConfig.map((p) => ({ config: p.config, batch: p.batch, batchSize: p.batchSize, wallMs: p.wallMs, filesScanned: p.filesScanned, findings: p.findings.length, errors: p.errors.length, exitCode: p.exitCode, overflow: p.overflow, parseError: p.parseError })),
    usage, filesScannedList: [...files].sort(), findings,
    perConfigDetail: perConfig.map((p) => ({ config: p.config, batch: p.batch, errors: p.errors, stderr: p.stderr })),
    generatedAt: new Date().toISOString(),
  };
  fs.writeFileSync(dest, JSON.stringify(record, null, 2));
  console.log('  GUARDADO ' + dest + '  wallTotal=' + (record.wallMsTotal / 1000).toFixed(1) + 's' +
    '  files=' + record.filesScannedUnion + '  findings=' + record.findingsTotal + '  errors=' + record.errorsTotal +
    '  peakRss=' + usage.peakRssMB + 'MB cpu=' + usage.cpuSec + 's');
})();
