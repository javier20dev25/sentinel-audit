'use strict';
const $ = (id) => document.getElementById(id);
const state = { repos: [], selectedRepo: null, selectedScan: null };
const installableTools = new Set(['codeql','semgrep','trivy','osv','bandit','shellcheck']);
const toolSources={codeql:'https://github.com/github/codeql-cli-binaries/releases',semgrep:'https://pypi.org/project/semgrep/',trivy:'https://github.com/aquasecurity/trivy/releases',osv:'https://github.com/google/osv-scanner/releases',bandit:'https://pypi.org/project/bandit/',shellcheck:'https://github.com/koalaman/shellcheck/releases'};
const headers = { 'content-type': 'application/json', 'x-sentinel-audit-request': 'ui' };

async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { ...(options.body ? headers : {}), ...(options.headers || {}) }, cache: 'no-store' });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
  return value;
}
function esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]); }
function evidencePath(value) { const text=String(value||'');const match=text.match(/[\\/]worktree[\\/](.+)$/i);if(match)return match[1].replace(/\\/g,'/');return /^[A-Za-z]:[\\/]/.test(text)?text.split(/[\\/]/).pop():text.replace(/\\/g,'/'); }
function displaySeverity(finding) { const value=finding.severity == null && finding.rawEngineSignal ? finding.rawEngineSignal.severity : finding.severity; if(typeof value==='number'||(typeof value==='string'&&/^\\d+$/.test(value)))return ({5:'CRITICAL',4:'HIGH',3:'MEDIUM',2:'LOW',1:'INFO'})[Number(value)]||'INFO'; return value||'INFO'; }
function toast(message) { const node = document.createElement('div'); node.className = 'toast'; node.textContent = message; document.body.append(node); setTimeout(() => node.remove(), 4000); }
function showModal(title, body, actions = '') {
  $('modal-root').innerHTML = `<div class="modal" role="dialog" aria-modal="true"><div class="modal-head"><h3>${esc(title)}</h3><button class="button subtle" data-close-modal aria-label="Cerrar">Cerrar</button></div>${body}${actions}</div>`;
  $('modal-root').onclick = (event) => { if (event.target === $('modal-root') || event.target.closest('[data-close-modal]')) $('modal-root').replaceChildren(); };
}
function go(view) {
  document.querySelectorAll('.view').forEach((el) => el.classList.toggle('active-view', el.id === `view-${view}`));
  document.querySelectorAll('.nav-item').forEach((el) => el.classList.toggle('active', el.dataset.view === view));
  $('current-view-label').textContent = ({ overview:'PR SCANNER', evidence:'EVIDENCE TRACE', database:'AUDIT STORAGE', analytics:'SCAN ANALYTICS', tools:'ENGINE REGISTRY', policies:'OPERATOR HANDBOOK', keys:'CLOUD ACCESS' })[view] || 'SENTINEL AUDIT';
  if (view === 'database') loadDatabase();
  if (view === 'analytics') loadAnalytics();
  if (view === 'keys') loadKeys();
}
document.querySelectorAll('.nav-item').forEach((button) => button.addEventListener('click', () => { go(button.dataset.view); document.body.classList.remove('mobile-nav-open'); }));
document.querySelectorAll('[data-goto]').forEach((button) => button.addEventListener('click', () => go(button.dataset.goto)));
const sidebarToggle=$('sidebar-toggle');
if(localStorage.getItem('sentinel-audit-sidebar-collapsed')==='true')document.body.classList.add('sidebar-collapsed');
sidebarToggle.addEventListener('click',()=>{document.body.classList.toggle('sidebar-collapsed');localStorage.setItem('sentinel-audit-sidebar-collapsed',String(document.body.classList.contains('sidebar-collapsed')));});
$('mobile-nav-toggle').addEventListener('click',()=>document.body.classList.toggle('mobile-nav-open'));
document.addEventListener('click',(event)=>{if(document.body.classList.contains('mobile-nav-open')&&event.target===document.body)document.body.classList.remove('mobile-nav-open');});

async function loadState() {
  try {
    const data = await api('/api/state');
    $('github-account').textContent = data.github && data.github.authenticated ? data.github.account : 'Sin sesión gh CLI';
    $('github-dot').classList.toggle('off', !(data.github && data.github.authenticated));
    $('db-location').textContent = data.database;
    $('footer-db').textContent = 'SQLITE / LOCAL';
    const active = data.tools.filter((tool) => tool.installed || tool.available).length;
    const cloud = data.cloud.enabled ? 'Pulse listo' : 'Pulse no disponible';
    $('status-grid').innerHTML = [
      card('GITHUB ACCOUNT', data.github && data.github.authenticated ? data.github.account : 'No autenticado', data.github && data.github.method || 'Usa gh auth login'),
      card('ANALYZERS FOUND', `${active} / ${data.tools.length}`, 'Detectados en este host; disponibilidad de ejecución por separado'),
      card('SENTINEL CLOUD', cloud, data.cloud.enabled ? `${data.cloud.keys.length} clave(s) local(es)` : data.cloud.reasons.join(' ')),
      card('AUDIT DATABASE', 'Conectada', 'Expedientes y etapas en SQLite local')
    ].join('');
    $('tool-list').innerHTML = data.tools.map((tool) => { const name=tool.name.toLowerCase();const label=tool.blockedByHost?'ENCONTRADO · BLOQUEADO POR GUARD':tool.available?'ENCONTRADO · LISTO':tool.installed?'ENCONTRADO · NO DISPONIBLE':'NO LOCALIZADO EN PATH'; const canInstall=installableTools.has(name)&&!tool.installed&&!tool.available; const installButton=canInstall?`<button class="button subtle" data-install-tool="${esc(name)}">Descargar e instalar</button>`:''; const source=toolSources[name]?`<a class="tool-source" href="${toolSources[name]}" target="_blank" rel="noreferrer">Fuente oficial</a>`:''; return `<div class="tool-row"><div class="recent-main"><strong>${esc(tool.name)}</strong><small>${esc(tool.reason || tool.state || 'Sin información')}</small>${tool.path?`<code>${esc(tool.path)}</code>`:''}${source}</div><span class="badge ${tool.available?'':'warn'}">${label}</span>${installButton}</div>`; }).join('');
    document.querySelectorAll('[data-install-tool]').forEach((button)=>button.addEventListener('click',()=>beginToolInstall(button.dataset.installTool)));
  } catch (error) { toast(`No se pudo consultar el estado local: ${error.message}`); }
}
function card(label, value, detail) { return `<article class="status-card"><small>${esc(label)}</small><strong>${esc(value)}</strong><span class="sub">${esc(detail)}</span></article>`; }
async function loadRepos() {
  $('repo-grid').innerHTML = '<div class="empty-state">Consultando repositorios permitidos por GitHub CLI…</div>';
  try {
    const result = await api('/api/repos'); state.repos = result.repositories || [];
    $('repo-count').textContent = `${state.repos.length} repositorios`;
    $('repo-grid').innerHTML = state.repos.length ? state.repos.map((repo) => `<article class="repo-card" data-repo="${esc(repo.nameWithOwner)}"><div class="repo-top"><span class="repo-name">${esc(repo.nameWithOwner)}</span><span class="visibility">${repo.isPrivate ? 'PRIVATE' : 'PUBLIC'}</span></div><p class="repo-desc">${esc(repo.description || 'Sin descripción registrada.')}</p><div class="repo-foot"><span>ABRIR PR INVENTORY</span><span>→</span></div></article>`).join('') : `<div class="empty-state">${esc(result.reason || 'No se encontraron repositorios visibles.')}</div>`;
    document.querySelectorAll('[data-repo]').forEach((el) => el.addEventListener('click', () => loadPulls(el.dataset.repo)));
  } catch (error) { $('repo-grid').innerHTML = `<div class="empty-state">No se pudo enumerar repositorios: ${esc(error.message)}</div>`; }
}
async function loadPulls(repo) {
  state.selectedRepo = repo; $('pr-panel').classList.remove('hidden'); $('selected-repo-label').textContent = `GITHUB REPOSITORY / ${repo}`; $('selected-repo-title').textContent = 'Pull Requests abiertos'; $('pr-list').innerHTML = '<div class="empty-state">Obteniendo PRs…</div>';
  try {
    const result = await api(`/api/repos/${encodeURIComponent(repo.split('/')[0])}/${encodeURIComponent(repo.split('/')[1])}/pulls`);
    const pulls = result.pullRequests || [];
    $('pr-list').innerHTML = pulls.length ? pulls.map((pr) => `<article class="pr-card"><div><h3>#${pr.number} ${esc(pr.title)}</h3><div class="pr-meta">@${esc(pr.author && pr.author.login || 'unknown')} · ${esc(pr.headRefName)} · SHA ${esc((pr.headRefOid || '').slice(0,12))}</div></div><div class="pr-actions"><button class="button primary" data-scan="${pr.number}" data-mode="lite">Escaneo Lite</button><button class="button" data-scan="${pr.number}" data-mode="pulse" ${window.auditCloudReady ? '' : 'disabled'} title="${esc(window.auditCloudReason || 'Pulse no disponible')}">Pulse</button></div></article>`).join('') : '<div class="empty-state">Este repositorio no tiene PRs abiertos.</div>';
    document.querySelectorAll('[data-scan]').forEach((button) => button.addEventListener('click', () => launchScan(repo, Number(button.dataset.scan), button.dataset.mode)));
  } catch (error) { $('pr-list').innerHTML = `<div class="empty-state">No se pudieron consultar los PRs: ${esc(error.message)}</div>`; }
}
async function refreshCloud() {
  const data = await api('/api/state'); window.auditCloudReady = data.cloud.enabled; window.auditCloudReason = data.cloud.reasons.join(' ');
  if (state.selectedRepo) await loadPulls(state.selectedRepo);
}
async function launchScan(repo, prNumber, mode) {
  let keyId;
  if (mode === 'pulse') {
    const data = await api('/api/state');
    if (!data.cloud.enabled) return toast(data.cloud.reasons.join(' '));
    if (data.cloud.keys.length > 1) {
      showModal('Elegir clave Cloud', `<div class="form-grid"><label>Clave censurada<select id="pulse-key" class="select">${data.cloud.keys.map((key) => `<option value="${esc(key.id)}">${esc(key.name)} · ${esc(key.maskedToken)}</option>`).join('')}</select></label></div>`, `<div class="form-actions"><button class="button subtle" data-close-modal>Cancelar</button><button class="button primary" id="pulse-confirm">Iniciar Pulse</button></div>`);
      await new Promise((resolve) => { $('pulse-confirm').onclick = () => { keyId = $('pulse-key').value; $('modal-root').replaceChildren(); resolve(); }; });
    } else keyId = data.cloud.keys[0].id;
  }
  try {
    const created = await api('/api/scans', { method: 'POST', body: JSON.stringify({ repo, prNumber, mode, keyId }) });
    go('evidence'); $('evidence-selection').textContent = `${repo} / PR #${prNumber} / ${mode.toUpperCase()}`;
    $('evidence-content').innerHTML = `<article class="scan-progress"><div class="scan-progress-head"><span class="live-dot"></span><strong>Analizando ${esc(repo)} · PR #${prNumber}</strong><span id="scan-stage-count">0 etapas</span></div><div class="scan-progress-track"><i></i></div><p>La ruta se construye con las etapas que el servidor confirma; no se estima un porcentaje de finalización.</p></article><div id="live-route" class="live-route" aria-live="polite"></div>`;
    pollScan(created.id);
  } catch (error) { toast(`No se pudo iniciar el escaneo: ${error.message}`); }
}
async function pollScan(id) {
  for (;;) {
    try {
      const data = await api(`/api/scans/${encodeURIComponent(id)}`);
      const live = $('live-route');
      if (live) {
        const events=data.events||[]; const count=$('scan-stage-count'); if(count)count.textContent=`${events.length} ${events.length===1?'etapa':'etapas'} registradas`;
        live.innerHTML = events.map((event,index) => {const stateName=String(event.state||'').toLowerCase();const cls=/complete|clean|success/.test(stateName)?'complete':/fail|error/.test(stateName)?'failed':/running|started/.test(stateName)?'running':'partial';const detail=typeof event.detail==='string'?event.detail:JSON.stringify(event.detail||'');return `<article class="live-route-node ${cls}" style="--route-index:${index}"><span class="route-node-index">${String(index+1).padStart(2,'0')}</span><div><h3>${esc(event.stage)}</h3><p>${esc(detail)}</p></div><span class="route-state">${esc(event.state)}</span></article>`;}).join('');
      }
      if (data.status === 'COMPLETE' && data.result) { state.selectedScan = id; renderEvidence(data.result); loadRecent(); return; }
      if (data.status === 'FAILED') { $('evidence-content').innerHTML += `<div class="finding-card sev-high"><h4>Escaneo incompleto</h4><p>${esc(data.error)}</p></div>`; return; }
      await new Promise((resolve) => setTimeout(resolve, 1100));
    } catch (error) { toast(`Se perdió la consulta de progreso: ${error.message}`); return; }
  }
}
async function beginToolInstall(tool) {
  const terms=tool==='codeql';
  const body=`<div class="install-confirm"><p>Se instalará en <code>%USERPROFILE%\\.sentinel-audit\\tools</code>, separado de otras aplicaciones. No requiere privilegios de administrador.</p><p>El instalador obtiene versiones oficiales y verifica SHA-256 cuando el proveedor publica un digest. Las herramientas Python usan un entorno virtual aislado y solo ruedas binarias.</p>${terms?'<label class="check-row"><input id="codeql-terms" type="checkbox"> Confirmo que el uso de CodeQL se limita a código abierto elegible o investigación académica, según sus términos.</label><p><a href="https://github.com/github/codeql-cli-binaries#terms-and-conditions" target="_blank" rel="noreferrer">Términos oficiales de CodeQL</a></p>':''}<div class="install-job" id="install-job"></div><div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cerrar</button><button type="button" class="button primary" id="install-confirm" ${terms?'disabled':''}>Iniciar instalación</button></div></div>`;
  showModal(`Instalar ${tool}`,body);
  if(terms)$('codeql-terms').addEventListener('change',(event)=>{$('install-confirm').disabled=!event.target.checked;});
  $('install-confirm').addEventListener('click',async(event)=>{const button=event.currentTarget;button.disabled=true;try{const job=await api('/api/tools/install',{method:'POST',body:JSON.stringify({tool,acceptLicenseTerms:terms&&$('codeql-terms').checked})});await pollToolInstall(job.id);}catch(error){$('install-job').innerHTML=`<p class="install-error">${esc(error.message)}</p>`;button.disabled=false;}});
}
async function pollToolInstall(id) {
  for(;;){try{const job=await api(`/api/tools/jobs/${encodeURIComponent(id)}`);const box=$('install-job');if(!box)return;box.innerHTML=`<div class="install-status"><strong>${esc(job.state)}</strong><span>${esc(job.message||'')}</span><progress max="100" value="${Number(job.percent)||0}"></progress><small>${Number(job.percent)||0}%</small>${job.error?`<p class="install-error">${esc(job.error)}</p>`:''}</div>`;if(['AVAILABLE','FAILED'].includes(job.state)){if(job.state==='AVAILABLE'){await loadState();toast(job.message);}const action=$('install-confirm');if(action)action.disabled=false;return;}await new Promise(resolve=>setTimeout(resolve,700));}catch(error){const box=$('install-job');if(box)box.innerHTML=`<p class="install-error">${esc(error.message)}</p>`;return;}}
}
function renderEvidence(body) {
  const audit = body.audit || {}; const stages = audit.stages || {}; const tools = audit.tools || {};
  const pipeline = ['PR metadata','Diff + SHA-256','Sentinel Lite / Pulse','Preflight','Commit pinned','Sentinel Audit core','Signal routing','Specialists','Correlation','Triage','Cleanup'];
  const nodes = pipeline.map((label, index) => {
    let status = index <= 2 ? 'complete' : 'partial'; let detail = index <= 2 ? 'COMPLETE' : 'NO EJECUTADO';
    if (index === 3) { detail = audit.preflight && audit.preflight.verdict || 'UNKNOWN'; status = detail === 'SKIP' ? 'failed' : 'complete'; }
    const stageName = ({4:'IDENTITY',5:'CLOUD',6:'ROUTING',7:'SPECIALISTS',8:'CORRELATION',9:'TRIAGE',10:'CLEANUP'})[index];
    if (stageName && stages[stageName]) { detail = stages[stageName].state; status = /COMPLETE|CLEAN/.test(detail) ? 'complete' : /FAILED|ERROR/.test(detail) ? 'failed' : 'partial'; }
    return `<div class="route-node ${status}">${esc(label)}<small>${esc(detail)}</small></div>`;
  }).join('');
  const specialistNodes = Object.entries(tools).filter(([name]) => name !== 'sentinel').map(([name, item]) => `<div class="route-node ${item.status === 'SUCCESS' ? 'complete' : item.status === 'ERROR' ? 'failed' : 'partial'}">${esc(name)}<small>${esc(item.status || 'NOT RUN')} · ${item.findingCount || 0} señales</small></div>`).join('');
  const findings = [...(body.lite && body.lite.findings || []).map((item) => ({...item, source:'Sentinel Lite'})), ...Object.entries(tools).flatMap(([source, item]) => (item.findings || []).map((finding) => ({...finding, source})))];
  const unique = new Map(); for (const finding of findings) unique.set(`${finding.source}|${finding.file}|${finding.line}|${finding.title}`, finding);
  const findingHtml = [...unique.values()].map((f) => { const severity=displaySeverity(f); return `<article class="finding-card sev-${esc(String(severity).toLowerCase())}"><h4>${esc(f.title || f.message || f.type || 'Señal')} <span class="badge ${['CRITICAL','HIGH'].includes(String(severity).toUpperCase()) ? 'danger' : ''}">${esc(severity)}</span></h4><p>${esc(f.description || f.detail || '')}</p><code>${esc(evidencePath(f.file) || 'ubicación desconocida')}${f.line ? `:${f.line}` : ''} · ${esc(f.source || 'analyzer')}</code>${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ''}</article>`; }).join('');
  const verdict = audit.auditVerdict && audit.auditVerdict.verdict || body.lite.verdict;
  const missing = Object.entries(tools).filter(([, t]) => ['UNAVAILABLE','ERROR','TIMEOUT','SKIPPED','INVALID'].includes(t.status)).map(([name]) => name);
  $('evidence-selection').textContent = `${body.repository} / PR #${body.pullRequest.number} / ${body.mode.toUpperCase()}`;
  $('evidence-content').innerHTML = `<div class="evidence-layout"><div><article class="glass-card"><p class="eyebrow">AUDIT PIPELINE / ${esc(audit.auditVerdict && audit.auditVerdict.analysisState || 'PARTIAL')}</p><h2>${esc(verdict)}</h2><p>${esc(audit.auditVerdict && audit.auditVerdict.statement || 'El resultado requiere revisión humana y se limita a la cobertura registrada.')}</p><div class="finding-card ${body.lite.verdict === 'BLOCK' ? 'sev-critical' : body.lite.verdict === 'REVIEW' ? 'sev-medium' : ''}"><h4>Sentinel Lite / ${esc(body.lite.verdict)} <span class="badge ${body.lite.verdict === 'BLOCK' ? 'danger' : ''}">RIESGO ${body.lite.riskScore}/100</span></h4><p>${body.lite.counts.critical} críticas · ${body.lite.counts.high} altas · ${body.lite.counts.medium} medias · ${body.lite.counts.low} bajas. Este veredicto pertenece al análisis del diff; el estado del pipeline y la cobertura se muestran por separado.</p></div></article><article class="map-card" style="margin-top:13px"><p class="eyebrow">EVIDENCE ROUTE / STATE PER STAGE</p><div class="route-map">${nodes}${specialistNodes}</div></article><div class="finding-list">${findingHtml || '<div class="empty-state">No se registraron hallazgos en las etapas completadas. Revisa los gaps de cobertura antes de interpretarlo como limpio.</div>'}</div></div><aside class="glass-card"><p class="eyebrow">IMMUTABLE REFERENCES</p><div class="hash-line"><strong>RESULT BODY SHA-256</strong><br>${esc(body.integrity.bodyHash)}</div><div class="hash-line" style="margin-top:14px"><strong>DIFF SHA-256</strong><br>${esc(body.diff.sha256)}</div><div class="hash-line" style="margin-top:14px"><strong>PINNED COMMIT</strong><br>${esc(body.pullRequest.commit)}</div><button class="button subtle" id="show-json" style="margin-top:15px;width:100%">Ver cuerpo JSON</button><button class="button subtle" id="download-json" style="margin-top:8px;width:100%">Descargar JSON</button><p class="eyebrow" style="margin-top:22px">TOOL COVERAGE GAPS</p><p class="muted">${missing.length ? `No completadas: ${esc(missing.join(', '))}` : 'Sin estados de especialista pendientes.'}</p>${missing.length ? `<button class="button" id="extend-scan" style="width:100%">Reintentar especialistas dirigidos</button><p class="muted">Solo herramientas justificadas por la ruta guardada. Las no seleccionadas por evidencia no se fuerzan.</p>` : ''}</aside></div>`;
  $('show-json').onclick = () => showModal('Cuerpo JSON del escaneo', `<pre>${esc(JSON.stringify(body, null, 2))}</pre>`);
  $('download-json').onclick = () => { const blob = new Blob([JSON.stringify(body, null, 2)], {type:'application/json'}); const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`sentinel-audit-${body.repository.replace('/','-')}-pr-${body.pullRequest.number}.json`;a.click();URL.revokeObjectURL(a.href); };
  if ($('extend-scan')) $('extend-scan').onclick = async () => {
    try { const updated = await api(`/api/scans/${encodeURIComponent(state.selectedScan)}/extend`, {method:'POST', body:JSON.stringify({tools:[]})}); renderEvidence(updated.result); toast('La ruta de especialistas se actualizó.'); }
    catch (error) { toast(`No se pudo ampliar el análisis: ${error.message}`); }
  };
}
async function loadRecent() {
  try { const { scans } = await api('/api/scans'); $('recent-scans').innerHTML = scans.length ? scans.slice(0,8).map((scan) => `<div class="recent-row" data-open-scan="${esc(scan.id)}"><div class="recent-main"><strong>${esc(scan.repo)} #${scan.pr_number} · ${esc(scan.verdict || scan.status)}</strong><small>${esc(scan.mode)} · ${esc(scan.started_at)} · ${scan.finding_count} registros</small></div><span class="badge ${scan.status === 'FAILED' ? 'danger' : ''}">${esc(scan.status)}</span></div>`).join('') : '<div class="empty-state">Todavía no hay escaneos guardados.</div>'; document.querySelectorAll('[data-open-scan]').forEach((row) => row.addEventListener('click', () => openScan(row.dataset.openScan))); }
  catch (error) { $('recent-scans').innerHTML = `<div class="empty-state">${esc(error.message)}</div>`; }
}
async function openScan(id) { try { const scan = await api(`/api/scans/${encodeURIComponent(id)}`); if (scan.result) { state.selectedScan=id; go('evidence'); renderEvidence(scan.result); } } catch (error) { toast(error.message); } }
async function loadDatabase() {
  try {
    const { table, rows } = await api(`/api/database?table=${encodeURIComponent($('db-table').value)}`);
    if (!rows.length) { $('data-table').innerHTML = '<tbody><tr><td>No hay registros.</td></tr></tbody>'; return; }
    const cols = Object.keys(rows[0]);
    $('data-table').innerHTML = `<thead><tr>${cols.map((c)=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${rows.map((row)=>`<tr>${cols.map((c)=>{const val=row[c];const display=typeof val==='string'?val:String(val??'');return `<td>${display.length>55||c.includes('json')||c==='detail'||c==='evidence'?`<span class="cell-long">${esc(display.slice(0,55))}</span><button class="cell-open" data-cell="${esc(encodeURIComponent(display))}" data-title="${esc(c)}">Ver</button>`:esc(display)}</td>`}).join('')}</tr>`).join('')}</tbody>`;
    document.querySelectorAll('[data-cell]').forEach((button)=>button.addEventListener('click',()=>showModal(`Registro / ${button.dataset.title}`,`<pre>${esc(decodeURIComponent(button.dataset.cell))}</pre>`)));
  } catch (error) { $('data-table').innerHTML = `<tbody><tr><td>${esc(error.message)}</td></tr></tbody>`; }
}
function chart(title, rows, labelKey, valueKey='count') {
  const max=Math.max(1,...rows.map(r=>Number(r[valueKey])||0));
  return `<article class="analytics-card"><h3>${esc(title)}</h3><div class="bars">${rows.length?rows.map((row)=>`<div class="bar-row"><span title="${esc(row[labelKey])}">${esc(row[labelKey]||'Sin categoría').slice(0,18)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2,(Number(row[valueKey])||0)/max*100)}%"></div></div><span>${Number(row[valueKey])||0}</span></div>`).join(''):'<span class="muted">Sin datos agregados.</span>'}</div></article>`;
}
function severityDonut(rows) {
  const colors={CRITICAL:'#d92e24',HIGH:'#f28522',MEDIUM:'#e5ba3c',LOW:'#5e9d8b',INFO:'#678099',UNSPECIFIED:'#a4a4a4'};
  const total=rows.reduce((sum,row)=>sum+(Number(row.count)||0),0); let cursor=0;
  const stops=rows.map((row)=>{const start=cursor;cursor+=total?(Number(row.count)||0)/total*100:0;return `${colors[row.severity]||'#aaa'} ${start}% ${cursor}%`;}).join(',');
  const legend=rows.map((row)=>`<li><i style="--swatch:${colors[row.severity]||'#aaa'}"></i><span>${esc(row.severity||'Sin clasificar')}</span><strong>${Number(row.count)||0}</strong></li>`).join('');
  return `<article class="analytics-card severity-card"><h3>Distribución de severidad</h3><div class="donut-layout"><div class="donut" style="--donut:${total?`conic-gradient(${stops})`:'conic-gradient(#d9d9d9 0 100%)'}"><div><strong>${total}</strong><small>hallazgos</small></div></div><ul class="donut-legend">${legend||'<li>Sin hallazgos</li>'}</ul></div></article>`;
}
function fileRanking(rows) { return `<article class="analytics-card"><h3>Archivos con más hallazgos</h3>${rows.length?`<ol class="file-ranking">${rows.map((row)=>`<li><code>${esc(row.file||'Sin ruta')}</code><strong>${Number(row.count)||0}</strong></li>`).join('')}</ol>`:'<p class="muted">Sin datos de archivo.</p>'}</article>`; }
function categoryTiles(rows) { const max=Math.max(1,...rows.map((r)=>Number(r.count)||0)); return `<article class="analytics-card"><h3>Tipos de señal</h3><div class="category-tiles">${rows.length?rows.map((row)=>`<div class="category-tile" style="--tile-weight:${Math.max(1,Number(row.count)||0)/max}"><span>${esc(row.category||'Sin categoría')}</span><strong>${Number(row.count)||0}</strong></div>`).join(''):'<p class="muted">Sin categorías.</p>'}</div></article>`; }
function timelineSvg(rows) { const width=640,height=180,pad=28,max=Math.max(1,...rows.map(r=>Number(r.count)||0));const points=rows.map((row,index)=>{const x=rows.length<2?width/2:pad+index*(width-pad*2)/(rows.length-1);const y=height-pad-(Number(row.count)||0)/max*(height-pad*2);return {x,y,row};});const poly=points.map(p=>`${p.x},${p.y}`).join(' ');return `<article class="analytics-card timeline-card"><h3>Actividad de escaneos · cronología</h3>${points.length?`<svg class="timeline-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Escaneos por fecha"><line x1="${pad}" y1="${height-pad}" x2="${width-pad}" y2="${height-pad}"/><line x1="${pad}" y1="${pad}" x2="${pad}" y2="${height-pad}"/><polyline points="${poly}"/>${points.map(p=>`<circle cx="${p.x}" cy="${p.y}" r="4"><title>${esc(p.row.day)}: ${Number(p.row.count)||0} escaneos</title></circle>`).join('')}${points.map(p=>`<text x="${p.x}" y="${height-6}" text-anchor="middle">${esc(p.row.day.slice(5))}</text>`).join('')}</svg>`:'<p class="muted">Sin escaneos registrados.</p>'}</article>`; }
async function loadAnalytics() {
  try { const d=await api('/api/analytics'); $('analytics-grid').innerHTML=severityDonut(d.severities)+chart('Hallazgos por motor',d.sources,'source')+fileRanking(d.files)+categoryTiles(d.categories)+timelineSvg(d.timeline); }
  catch (error) { $('analytics-grid').innerHTML=`<div class="empty-state">${esc(error.message)}</div>`; }
}
async function loadKeys() {
  try { const data=await api('/api/state'); const cloud=data.cloud; window.auditCloudReady=cloud.enabled;window.auditCloudReason=cloud.reasons.join(' '); $('key-list').innerHTML=cloud.keys.length?cloud.keys.map((key)=>`<div class="key-row"><div class="key-info"><strong>${esc(key.name)}</strong><code>${esc(key.maskedToken)}</code><small class="muted">Agregada ${esc(key.addedAt||'')}</small></div><button class="button danger" data-revoke="${esc(key.id)}">Eliminar localmente</button></div>`).join(''):'<div class="empty-state">No hay claves de Sentinel Cloud guardadas. Pulse permanecerá desactivado.</div>';document.querySelectorAll('[data-revoke]').forEach((button)=>button.addEventListener('click',async()=>{if(!confirm('Eliminar esta clave del almacén local? Esto no revoca el token en Sentinel Cloud.'))return;try{const result=await api(`/api/keys/${encodeURIComponent(button.dataset.revoke)}`,{method:'DELETE'});toast(result.warning);loadKeys();loadState();refreshCloud();}catch(error){toast(error.message)}})); }
  catch(error){$('key-list').innerHTML=`<div class="empty-state">${esc(error.message)}</div>`;}
}
$('add-key-open').addEventListener('click',()=>showModal('Agregar clave Sentinel Cloud',`<form id="key-form" class="form-grid"><label>Nombre visible<input name="name" maxlength="60" placeholder="Producción, investigación…" required></label><label>Token API<input name="token" type="password" autocomplete="new-password" required minlength="6"></label><p class="muted">El token se guarda mediante el almacén local de Sentinel Audit. La aplicación web nunca lo vuelve a mostrar.</p><div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cancelar</button><button class="button primary">Guardar clave</button></div></form>`));
$('modal-root').addEventListener('submit',async(event)=>{if(event.target.id!=='key-form')return;event.preventDefault();const form=new FormData(event.target);try{await api('/api/keys',{method:'POST',body:JSON.stringify({name:form.get('name'),token:form.get('token')})});$('modal-root').replaceChildren();toast('Clave guardada en el almacén local.');loadKeys();loadState();refreshCloud();}catch(error){toast(error.message)}});
$('db-table').addEventListener('change',loadDatabase);$('refresh-repos').addEventListener('click',loadRepos);$('close-prs').addEventListener('click',()=>$('pr-panel').classList.add('hidden'));$('refresh-analytics').addEventListener('click',loadAnalytics);
Promise.all([loadState(),loadRepos(),loadRecent(),refreshCloud()]);
