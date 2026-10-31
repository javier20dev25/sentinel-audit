'use strict';
const $ = (id) => document.getElementById(id);
const state = { repos: [], selectedRepo: null, selectedScan: null, view: 'overview', prOpen: false, readOnlyEvidence: false };
const installableTools = new Set(['codeql','semgrep','trivy','osv','zizmor','bandit','shellcheck']);
const toolSources={codeql:'https://github.com/github/codeql-cli-binaries/releases',semgrep:'https://pypi.org/project/semgrep/',trivy:'https://github.com/aquasecurity/trivy/releases',osv:'https://github.com/google/osv-scanner/releases',zizmor:'https://docs.zizmor.sh/installation/',bandit:'https://pypi.org/project/bandit/',shellcheck:'https://github.com/koalaman/shellcheck/releases'};
const headers = { 'content-type': 'application/json', 'x-sentinel-audit-request': 'ui' };
window.auditLocalReady = false; window.auditLocalReason = 'Consultando disponibilidad del motor local.'; window.auditCloudReady = false; window.auditCloudReason = 'Consultando Sentinel Cloud.'; window.auditCloudKeys = 0;

async function api(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { ...(options.body ? headers : {}), ...(options.headers || {}) }, cache: 'no-store' });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.error || `HTTP ${response.status}`);
  return value;
}
function esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]); }
function evidencePath(value) { const text=String(value||'');const match=text.match(/[\\/]worktree[\\/](.+)$/i);if(match)return match[1].replace(/\\/g,'/');return /^[A-Za-z]:[\\/]/.test(text)?text.split(/[\\/]/).pop():text.replace(/\\/g,'/'); }
function displaySeverity(finding) {
  let value = finding.severity == null && finding.rawEngineSignal ? finding.rawEngineSignal.severity : finding.severity;
  if (value == null) value = finding.level;
  if (typeof value === 'number' || (typeof value === 'string' && /^\d+$/.test(value))) return ({ 5:'CRITICAL',4:'HIGH',3:'MEDIUM',2:'LOW',1:'INFO' })[Number(value)] || 'INFO';
  const named = String(value == null ? '' : value).toUpperCase();
  return ({ ERROR:'HIGH', WARNING:'MEDIUM', NOTE:'LOW' })[named] || named || 'INFO';
}
function ruleLabel(finding) {
  const rule = finding.rule;
  if (typeof rule === 'string') return rule;
  if (rule && typeof rule === 'object') return rule.id || rule.message || rule.title || null;
  return null;
}
function findingTitle(finding) {
  const candidates = [finding.title, finding.message, finding.name, ruleLabel(finding), finding.checkId, finding.ruleId, finding.detail, typeof finding.type === 'string' ? finding.type : null, finding.kind];
  const label = candidates.find((value) => typeof value === 'string' && value.trim());
  return label ? label.slice(0, 300) : 'Señal sin título';
}
function findingDetail(finding) {
  const candidates = [finding.description, finding.detail, finding.message, finding.rule && typeof finding.rule === 'object' ? finding.rule.message : null];
  const label = candidates.find((value) => typeof value === 'string' && value.trim());
  return label ? label : '';
}
function findingSnippet(finding) {
  const snippet = finding.snippet;
  if (!snippet) return '';
  if (typeof snippet === 'string') return snippet;
  if (typeof snippet === 'object') return snippet.text || snippet.content || snippet.lines || '';
  return '';
}
function findingFile(finding) { return finding.file || finding.path || (finding.location && finding.location.path) || ''; }
function findingLine(finding) { const value = finding.line || (finding.location && finding.location.line); return Number.isInteger(value) ? value : null; }
function findingSource(finding) { return finding.source || finding.tool || finding.engine || 'analyzer'; }
function evidenceText(value) { if (value == null) return ''; if (typeof value === 'string') return value; try { return JSON.stringify(value); } catch (_) { return String(value); } }
function githubPrUrl(body) {
  const repo = String(body && body.repository || ''); const number = Number(body && body.pullRequest && body.pullRequest.number);
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || !Number.isSafeInteger(number) || number < 1) return '';
  return `https://github.com/${repo}/pull/${number}/files`;
}
function githubEvidenceLink(body, file, line, label = 'Abrir evidencia en GitHub ↗') {
  const prUrl = githubPrUrl(body);
  if (!prUrl) return '';
  const repo = String(body.repository); const sha = String(body.pullRequest && body.pullRequest.commit || '');
  const normalized = evidencePath(file).replace(/\\/g, '/');
  const segments = normalized.split('/');
  const safeFile = !!normalized && !normalized.startsWith('/') && !/^[A-Za-z]:/.test(normalized) && !normalized.includes('\0') && segments.every((segment) => segment && segment !== '.' && segment !== '..' && !/[<>:"|?*]/.test(segment));
  const target = safeFile && /^[a-f0-9]{40,64}$/i.test(sha)
    ? `https://github.com/${repo}/blob/${sha}/${segments.map(encodeURIComponent).join('/')}${Number.isInteger(Number(line)) && Number(line) > 0 ? `#L${Number(line)}` : ''}`
    : prUrl;
  return `<a class="github-evidence-link" href="${esc(target)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`;
}
const SIGNAL_NATURE = {
  malicious: { id: 'malicious', label: 'Indicador de comportamiento malicioso', short: 'MALICIOSO', detail: 'Patrones asociados a ejecución no solicitada, exfiltración, persistencia u ofuscación. Requiere confirmación humana.' },
  defect: { id: 'defect', label: 'Defecto de seguridad', short: 'DEFECTO', detail: 'Patrones compatibles con una vulnerabilidad de implementación; no implican intención.' },
  unclassified: { id: 'unclassified', label: 'Sin clasificación heurística', short: 'SIN CLASE', detail: 'El texto del hallazgo no coincide con los patrones conocidos del clasificador.' }
};
const MALICIOUS_SIGNALS = [/obfuscat/, /base64/, /eval\s*\(/, /child_process/, /\bexec(sync|file|spawn)?\s*\(/, /(curl|wget)[^|\n]*\|/, /powershell[^\n]*-enc/, /exfiltrat/, /credential (dump|harvest|theft)/, /reverse shell/, /backdoor/, /crypto ?(miner|mining)/, /(keylog|stealer)/, /download[^\n]*(exec|run)/, /(postinstall|preinstall)/, /command and control|\bc2\b/, /persist(ence|ent)/, /rm -rf/, /chmod \+x/, /(trojan|ransomware|worm)/];
const DEFECT_SIGNALS = [/injection/, /cross[- ]site|\bxss\b/, /(path|directory) traversal/, /\bssrf\b|server[- ]side request forgery/, /\bcsrf\b/, /deserializ/, /prototype pollution/, /insecure/, /missing (auth|authorization|validation)/, /auth(?:entication|orization)? bypass/, /hardcoded (secret|password|key|token)/, /weak (crypto|hash|cipher)/, /plaintext/, /unvalidated/, /sanitiz/, /race condition/, /misconfig/, /cve-\d{4}-\d+/, /vulnerab/, /(open redirect|information disclosure)/, /(integer|buffer) overflow/, /(permission|privilege) (escalation|check)/];
function signalNatureText(finding) {
  const parts = [finding.__title, finding.title, finding.description, finding.message, finding.detail, finding.category, finding.kind, finding.type, finding.ruleId, finding.rule];
  for (const key of ['tags', 'evidence', 'signals']) if (Array.isArray(finding[key])) parts.push(...finding[key]);
  return parts.filter((value) => typeof value === 'string').join(' ').toLowerCase();
}
function classifySignalNature(finding) {
  const text = signalNatureText(finding);
  let malicious = 0; let defect = 0;
  for (const pattern of MALICIOUS_SIGNALS) if (pattern.test(text)) malicious++;
  for (const pattern of DEFECT_SIGNALS) if (pattern.test(text)) defect++;
  if (malicious && malicious >= defect) return { ...SIGNAL_NATURE.malicious, malicious, defect };
  if (defect) return { ...SIGNAL_NATURE.defect, malicious, defect };
  return { ...SIGNAL_NATURE.unclassified, malicious, defect };
}
function renderSignalNature(findings) {
  if (!findings.length) return '';
  const groups = { malicious: [], defect: [], unclassified: [] };
  for (const finding of findings) groups[classifySignalNature(finding).id].push(finding);
  const cards = Object.values(SIGNAL_NATURE).map((nature) => `<div class="nature-card nature-${nature.id}"><span class="badge nature-${nature.id}">${esc(nature.short)}</span><strong>${groups[nature.id].length}</strong><p>${esc(nature.label)}</p><small>${esc(nature.detail)}</small></div>`).join('');
  return `<section class="signal-nature"><div class="analysis-section-title"><h3>Naturaleza de las señales</h3><span>Clasificación heurística · ${findings.length} hallazgo(s)</span></div><div class="nature-grid">${cards}</div><p class="nature-caveat">Esta separación se calcula sobre el texto y la categoría del hallazgo. No atribuye intención ni distingue con certeza entre un error del desarrollador y una acción deliberada; esa conclusión requiere contexto del cambio y revisión humana.</p></section>`;
}
function renderSignalFlow(signal) {
  if (!signal) return '<p class="flow-empty">Esta señal no incluye una ruta estructurada.</p>';
  const pathValue = signal.path;
  const pathSteps = Array.isArray(pathValue) ? pathValue : pathValue && typeof pathValue === 'object' ? (pathValue.steps || pathValue.nodes || pathValue.path || []) : [];
  const steps = Array.isArray(pathSteps) ? pathSteps : [];
  const nodes = [];
  const source = evidenceText(signal.source || signal.sourceFile);
  const sink = evidenceText(signal.sink);
  if (source) nodes.push({ kind: 'SOURCE', label: source });
  for (const step of steps) nodes.push({ kind: 'PATH', label: evidenceText(step && typeof step === 'object' ? (step.label || step.name || step.location || step.file || step.node || step) : step) });
  if (typeof pathValue === 'string' && pathValue && !steps.length && !source && !sink) nodes.push({ kind: 'PATH', label: pathValue });
  if (sink) nodes.push({ kind: 'SINK', label: sink });
  if (!nodes.length) return '<p class="flow-empty">La señal no trae source, sink ni pasos de flujo; consulta el detalle normalizado.</p>';
  return `<div class="flow-strip">${nodes.map((node,index)=>`${index?'<span class="flow-arrow" aria-hidden="true">→</span>':''}<div class="flow-node"><small>${esc(node.kind)}</small><strong>${esc(node.label)}</strong></div>`).join('')}</div>`;
}
function renderCandidateCard(candidate, index) {
  const signals = candidate.signals || candidate.evidence || [];

  const flowSignal = signals.find((signal) => signal.source || signal.sink || signal.path);
  const file = evidencePath(candidate.file) || 'ubicación desconocida';
  const line = candidate.line || candidate.startLine;
  const authorities = candidate.corroboratingAuthorities || candidate.tools || [];
  const label = candidate.message || candidate.rule || 'Señal correlacionada';
  return `<article class="candidate-card" role="button" tabindex="0" data-candidate="${index}"><div class="candidate-card-head"><span class="candidate-id">${esc(candidate.candidateId || 'CANDIDATE')}</span><span class="severity-pill sev-${esc(String(candidate.severity || 'review').toLowerCase())}">${esc(candidate.severity || 'REVISIÓN')}</span></div><h4>${esc(label)}</h4><div class="candidate-meta"><code class="candidate-location">${esc(file)}${line ? `:${esc(line)}` : ''}</code><span>${signals.length} señales</span><span>${esc(candidate.confidence || 'sin nivel de corroboración')}</span></div><div class="candidate-meta">Autoridades: ${esc(authorities.join(', ') || 'sin lista registrada')}</div>${renderSignalFlow(flowSignal)}<p class="candidate-caveat">Corroboración entre herramientas; no es una probabilidad. Requiere verificación humana.</p></article>`;
}
function renderObservation(item, body, index) {
  const file = item.file || item.path || (item.location && item.location.path);
  const line = item.line || item.startLine || (item.location && item.location.line);
  const signals = Array.isArray(item.signals) ? item.signals : Array.isArray(item.evidence) ? item.evidence : [];
  const signalEvidence = signals.map((signal, signalIndex) => {
    const signalFile = signal.file || signal.path || (signal.location && signal.location.path) || file;
    const signalLine = signal.line || (signal.location && signal.location.line) || line;
    return `<article class="observation-signal"><strong>${esc(signal.tool || signal.authority || signal.source || `Señal ${signalIndex + 1}`)}</strong><small>${esc(signal.rule || signal.signalClass || signal.status || 'sin regla')}</small><p>${esc(signal.detail || signal.message || signal.verdictFromTool || 'Sin descripción textual del motor.')}</p>${renderSignalFlow(signal)}${githubEvidenceLink(body, signalFile, signalLine)}<details><summary>JSON de la señal</summary><pre class="evidence-json">${esc(JSON.stringify(signal, null, 2))}</pre></details></article>`;
  }).join('');
  return `<article class="candidate-detail observation-detail"><div class="observation-title"><strong>${esc(item.observationId || `OBSERVACIÓN ${index + 1}`)} · ${esc(evidencePath(file) || 'ubicación desconocida')}${line ? `:${esc(line)}` : ''}</strong>${githubEvidenceLink(body, file, line)}</div><p class="observation-note">${esc(item.note || item.status || 'Señal sin autoridad suficiente para promover un candidato.')}</p><small>${esc((item.tools || []).join(', '))} · ${Number(item.signalCount || signals.length || 0)} señales</small><details class="observation-evidence"><summary>Ver evidencia y datos normalizados</summary>${signalEvidence ? `<div class="observation-signals">${signalEvidence}</div>` : `<p class="muted">No hay señales separadas; se muestra el objeto completo registrado por el correlador.</p>`}<pre class="evidence-json">${esc(JSON.stringify(item, null, 2))}</pre></details></article>`;
}
function toast(message) { const node = document.createElement('div'); node.className = 'toast'; node.textContent = message; document.body.append(node); setTimeout(() => node.remove(), 4000); }
function showModal(title, body, actions = '') {
  $('modal-root').innerHTML = `<div class="modal" role="dialog" aria-modal="true"><div class="modal-head"><h3>${esc(title)}</h3><button class="button subtle" data-close-modal aria-label="Cerrar">Cerrar</button></div>${body}${actions}</div>`;
  $('modal-root').onclick = (event) => { if (event.target === $('modal-root') || event.target.closest('[data-close-modal]')) $('modal-root').replaceChildren(); };
}
function updateBackButton() {
  const button = $('back-button');
  if (!button) return;
  const visible = state.prOpen || state.view !== 'overview';
  button.classList.toggle('hidden', !visible);
  button.textContent = state.view === 'overview' && state.prOpen ? '← Repositorios' : '← Volver';
}
function closePulls() {
  $('pr-panel').classList.add('hidden');
  state.prOpen = false;
  document.querySelectorAll('.repo-card.selected').forEach((el) => el.classList.remove('selected'));
  updateBackButton();
  $('repo-grid').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function goBack() {
  if (state.view !== 'overview') { go('overview'); return; }
  if (state.prOpen) closePulls();
}
function go(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach((el) => el.classList.toggle('active-view', el.id === `view-${view}`));
  document.querySelectorAll('.nav-item').forEach((el) => el.classList.toggle('active', el.dataset.view === view));
  $('current-view-label').textContent = ({ overview:'PR SCANNER', evidence:'EVIDENCE TRACE', forensics:'FORENSIC SEARCH', database:'AUDIT STORAGE', analytics:'SCAN ANALYTICS', tools:'ENGINE REGISTRY', policies:'OPERATOR HANDBOOK', keys:'CLOUD ACCESS' })[view] || 'SENTINEL AUDIT';
  updateBackButton();
  if (view === 'database') loadDatabase();
  if (view === 'forensics') searchForensics();
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
    window.auditLocalReady = !!(data.localEngine && data.localEngine.available); window.auditLocalReason = data.localEngine && data.localEngine.reason || 'Motor local completo no disponible.'; window.auditCloudReady = !!(data.cloud && data.cloud.enabled); window.auditCloudKeys = data.cloud && data.cloud.keys ? data.cloud.keys.length : 0; window.auditCloudReason = data.cloud && data.cloud.reasons.join(' ') || '';
    $('github-account').textContent = data.github && data.github.authenticated ? data.github.account : 'Sin sesión gh CLI';
    $('github-dot').classList.toggle('off', !(data.github && data.github.authenticated));
    $('db-location').textContent = data.database;
    $('footer-db').textContent = 'SQLITE / LOCAL';
    const specialists = data.tools.filter((tool) => tool.category === 'specialist');
    const active = specialists.filter((tool) => tool.installed || tool.available).length;
    const cloud = data.cloud.enabled ? 'Pulse listo' : 'Pulse no disponible';
    $('status-grid').innerHTML = [
      card('GITHUB ACCOUNT', data.github && data.github.authenticated ? data.github.account : 'No autenticado', data.github && data.github.method || 'Usa gh auth login'),
      card('SPECIALISTS FOUND', `${active} / ${specialists.length}`, 'Analizadores externos detectados; Lite diff integrado y motor local verificado por separado'),
      card('SENTINEL CLOUD', data.cloud.enabled ? cloud : data.cloud.keys.length ? `${data.cloud.keys.length} CLAVE(S) GUARDADA(S)` : 'SIN CLAVE', data.cloud.enabled ? `Pulse listo · ${data.cloud.endpointHost || 'endpoint local'}` : data.cloud.reasons.join(' ')),
      card('AUDIT DATABASE', 'Conectada', 'Expedientes y etapas en SQLite local')
    ].join('');
    $('tool-list').innerHTML = data.tools.map((tool) => renderToolRow(tool)).join('');
    $('tool-list').querySelectorAll('[data-install-tool]').forEach((button) => button.addEventListener('click', () => beginToolInstall(button.dataset.installTool, button)));
    $('tool-list').querySelectorAll('[data-goto]').forEach((button) => button.addEventListener('click', () => go(button.dataset.goto)));
  } catch (error) { toast(`No se pudo consultar el estado local: ${error.message}`); }
}
function card(label, value, detail) { return `<article class="status-card"><small>${esc(label)}</small><strong>${esc(value)}</strong><span class="sub">${esc(detail)}</span></article>`; }
function prSeverityPanel(pulls) {
  const scanned = pulls.filter((pr) => pr.latestAudit && pr.latestAudit.status === 'COMPLETE');
  const counts = new Map();
  for (const pr of scanned) for (const row of pr.latestAudit.severities || []) {
    const severity = String(row.severity || 'UNSPECIFIED').toUpperCase();
    counts.set(severity, (counts.get(severity) || 0) + Number(row.count || 0));
  }
  const order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNSPECIFIED'];
  const colors = { CRITICAL:'#d92e24', HIGH:'#f28522', MEDIUM:'#e5ba3c', LOW:'#5e9d8b', INFO:'#678099', UNSPECIFIED:'#a4a4a4' };
  const total = [...counts.values()].reduce((sum, count) => sum + count, 0);
  const rows = order.filter((severity) => counts.has(severity)).map((severity) => ({ severity, count: counts.get(severity), percent: total ? Math.round(counts.get(severity) / total * 100) : 0 }));
  let cursor = 0;
  const stops = rows.map((row) => { const start = cursor; cursor += total ? row.count / total * 100 : 0; return `${colors[row.severity]} ${start}% ${cursor}%`; }).join(',');
  const legend = rows.map((row) => `<li><i style="--swatch:${colors[row.severity]}"></i><span>${esc(row.severity === 'UNSPECIFIED' ? 'SIN CLASIFICAR' : row.severity)}</span><strong>${row.percent}% <small>(${row.count})</small></strong></li>`).join('');
  const stateText = !scanned.length ? 'Aún no hay un escaneo completo guardado para los PR abiertos de este repositorio.' : total ? 'Porcentaje sobre los hallazgos del último escaneo completo de cada PR abierta.' : 'Los últimos escaneos completos no registraron hallazgos de severidad.';
  return `<section class="pr-analytics"><div class="pr-analytics-heading"><div><p class="eyebrow">SEVERIDAD · PR ABIERTAS</p><h3>Distribución de hallazgos</h3><small>${scanned.length} de ${pulls.length} PR con último escaneo completo</small></div><p>${esc(stateText)}</p></div><div class="donut-layout"><div class="donut" style="--donut:${total ? `conic-gradient(${stops})` : 'conic-gradient(#44505c 0 100%)'}"><div><strong>${total}</strong><small>hallazgos</small></div></div><ul class="donut-legend">${legend || `<li>${scanned.length ? '0 hallazgos' : 'Sin datos de escaneo'}</li>`}</ul></div></section>`;
}
function toolBadge(tool) {
  if (tool.id === 'sentinel-local') return { label: 'LITE · LISTO', cls: '' };
  if (tool.id === 'sentinel-engine-local') return tool.available ? { label: 'MOTOR LOCAL · LISTO', cls: '' } : { label: 'MOTOR LOCAL · NO DISPONIBLE', cls: 'warn' };
  if (tool.id === 'sentinel-cloud') return tool.available ? { label: 'PULSE HABILITADO', cls: '' } : { label: 'PULSE NO CONFIGURADO', cls: 'warn' };
  if (tool.blockedByHost) return { label: 'ENCONTRADO · BLOQUEADO POR GUARD', cls: 'warn' };
  if (tool.available) return { label: 'ENCONTRADO · LISTO', cls: '' };
  if (tool.state === 'INVALID') return { label: 'RUTA ROTA · REINSTALAR', cls: 'warn' };
  if (tool.installed) return { label: 'INSTALADO · NO DISPONIBLE', cls: 'warn' };
  return { label: 'NO INSTALADO', cls: 'warn' };
}
function renderToolRow(tool) {
  const id = tool.id || String(tool.name || '').toLowerCase();
  const badge = toolBadge(tool);
  const source = toolSources[id] ? `<a class="tool-source" href="${toolSources[id]}" target="_blank" rel="noreferrer">Fuente oficial</a>` : '';
  const canInstall = (tool.installable === true || installableTools.has(id)) && (!tool.installed || tool.state === 'INVALID') && !tool.available;
  const installButton = canInstall ? `<button type="button" class="button subtle" data-install-tool="${esc(id)}">Descargar e instalar</button>` : '';
  const configureButton = id === 'sentinel-cloud' && !tool.available ? '<button type="button" class="button subtle" data-goto="keys">Configurar clave</button>' : '';
  return `<div class="tool-row"><div class="recent-main"><strong>${esc(tool.name)}</strong><small>${esc(tool.reason || tool.state || 'Sin información')}</small>${tool.path ? `<code>${esc(tool.path)}</code>` : ''}${source}</div><span class="badge ${badge.cls}">${esc(badge.label)}</span>${installButton || configureButton}</div>`;
}
async function loadRepos(options = {}) {
  const refreshing = state.repos.length > 0;
  if (!refreshing) $('repo-grid').innerHTML = '<div class="empty-state">Consultando repositorios permitidos por GitHub CLI…</div>';
  else $('repo-count').textContent = 'Actualizando…';
  try {
    const result = await api('/api/repos'); state.repos = result.repositories || [];
    $('repo-count').textContent = `${state.repos.length} repositorios`;
    $('repo-grid').innerHTML = state.repos.length ? state.repos.map((repo) => `<article class="repo-card" role="button" tabindex="0" data-repo="${esc(repo.nameWithOwner)}"><div class="repo-top"><span class="repo-name">${esc(repo.nameWithOwner)}</span><span class="visibility">${repo.isPrivate ? 'PRIVATE' : 'PUBLIC'}</span></div><span class="repo-pr-badge ${repo.openPrCount === null ? 'unknown' : ''}" title="${repo.openPrCount === null ? 'No se pudo consultar el conteo de PRs' : `${repo.openPrCount} PR abiertas en GitHub`}"><strong>${repo.openPrCount === null ? '—' : repo.openPrCount}</strong><small>PR ABIERTAS</small></span><p class="repo-desc">${esc(repo.description || 'Sin descripción registrada.')}</p><div class="repo-foot"><span>ABRIR PR INVENTORY</span><span>→</span></div></article>`).join('') : `<div class="empty-state">${esc(result.reason || 'No se encontraron repositorios visibles.')}</div>`;
    document.querySelectorAll('.repo-card[data-repo]').forEach((el) => {
      el.addEventListener('click', () => loadPulls(el.dataset.repo));
      el.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); loadPulls(el.dataset.repo); } });
    });
  } catch (error) {
    if (refreshing) { $('repo-count').textContent = `${state.repos.length} repositorios`; toast(`No se pudo actualizar la lista: ${error.message}`); }
    else $('repo-grid').innerHTML = `<div class="empty-state">No se pudo enumerar repositorios: ${esc(error.message)}</div>`;
  }
}
async function loadPulls(repo) {
  state.selectedRepo = repo; state.prOpen = true; $('pr-panel').classList.remove('hidden'); $('selected-repo-label').textContent = `GITHUB REPOSITORY / ${repo}`; $('selected-repo-title').textContent = 'Pull Requests abiertos'; $('pr-list').innerHTML = '<div class="empty-state">Obteniendo PRs…</div>';
  updateBackButton();
  document.querySelectorAll('.repo-card[data-repo]').forEach((el) => el.classList.toggle('selected', el.dataset.repo === repo));
  $('pr-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const readiness = await api('/api/state');
    window.auditLocalReady = !!(readiness.localEngine && readiness.localEngine.available);
    window.auditLocalReason = readiness.localEngine && readiness.localEngine.reason || 'Motor local completo no disponible.';
    window.auditCloudReady = !!(readiness.cloud && readiness.cloud.enabled);
    window.auditCloudKeys = readiness.cloud && readiness.cloud.keys ? readiness.cloud.keys.length : 0;
    window.auditCloudReason = readiness.cloud && readiness.cloud.reasons ? readiness.cloud.reasons.join(' ') : 'Pulse requiere configurar Sentinel Cloud.';
    const result = await api(`/api/repos/${encodeURIComponent(repo.split('/')[0])}/${encodeURIComponent(repo.split('/')[1])}/pulls`);
    const pulls = result.pullRequests || [];
    $('pr-analytics').innerHTML = pulls.length ? prSeverityPanel(pulls) : '';
    $('pr-list').innerHTML = pulls.length ? pulls.map((pr) => {
      const labels = (pr.labels || []).map((label) => typeof label === 'string' ? label : label.name).filter(Boolean);
      const auditStatus = pr.latestAudit ? `${pr.latestAudit.status} · ${pr.latestAudit.mode} · ${String(pr.latestAudit.startedAt || '').slice(0,10)}` : 'Sin escaneo local guardado';
      const pulseButton = window.auditCloudReady
        ? `<button class="button" data-scan="${pr.number}" data-mode="pulse">Sentinel Cloud · Pulse</button>`
        : window.auditCloudKeys > 0
          ? `<button class="button" data-configure-pulse data-pending-scan="${pr.number}" title="${esc(window.auditCloudReason)}">Activar Pulse</button><small class="pulse-block-reason">Clave detectada · configuración pendiente</small>`
          : `<button class="button subtle" data-configure-pulse title="${esc(window.auditCloudReason)}">Configurar Pulse</button><small class="pulse-block-reason">${esc(window.auditCloudReason)}</small>`;
      return `<article class="pr-card"><div><h3>#${pr.number} ${esc(pr.title)}</h3><div class="pr-meta">@${esc(pr.author && pr.author.login || 'unknown')} · ${esc(pr.headRefName)} · SHA ${esc((pr.headRefOid || '').slice(0,12))}</div><div class="pr-meta pr-audit-meta">Último escaneo: ${esc(auditStatus)}</div>${labels.length ? `<div class="pr-labels">${labels.map((label)=>`<span class="visibility">${esc(label)}</span>`).join('')}</div>` : ''}</div><div class="pr-actions"><button class="button primary" data-scan="${pr.number}" data-mode="lite">Lite · diff</button>${window.auditLocalReady ? `<button class="button" data-scan="${pr.number}" data-mode="local">Motor local</button>` : `<button class="button" disabled title="${esc(window.auditLocalReason || 'Motor local completo no disponible')}">Motor local</button>`}${pulseButton}</div></article>`;
    }).join('') : '<div class="empty-state">Este repositorio no tiene PRs abiertos.</div>';
    document.querySelectorAll('[data-scan]').forEach((button) => button.addEventListener('click', () => launchScan(repo, Number(button.dataset.scan), button.dataset.mode)));
    document.querySelectorAll('[data-configure-pulse]').forEach((button) => button.addEventListener('click', (event) => configureCloudPulse({ pendingScan: Number(event.currentTarget.dataset.pendingScan) || null })));
  } catch (error) { $('pr-list').innerHTML = `<div class="empty-state">No se pudieron consultar los PRs: ${esc(error.message)}</div>`; }
}
async function refreshCloud() {
  const data = await api('/api/state'); window.auditLocalReady = !!(data.localEngine && data.localEngine.available); window.auditLocalReason = data.localEngine && data.localEngine.reason || 'Motor local completo no disponible.'; window.auditCloudReady = data.cloud.enabled; window.auditCloudKeys = data.cloud.keys ? data.cloud.keys.length : 0; window.auditCloudReason = data.cloud.reasons.join(' ');
  if (state.selectedRepo) await loadPulls(state.selectedRepo);
}
async function launchScan(repo, prNumber, mode) {
  const modeLabel = ({ lite: 'SENTINEL AUDIT LITE · DIFF', local: 'SENTINEL LOCAL · MOTOR COMPLETO', pulse: 'SENTINEL CLOUD · PULSE' })[mode] || 'SENTINEL AUDIT';
  let keyId;
  if (mode === 'pulse') {
    const data = await api('/api/state');
    if (!data.cloud.enabled) { go('keys'); return toast(data.cloud.reasons.join(' ')); }
    if (data.cloud.keys.length > 1) {
      showModal('Elegir clave Cloud', `<div class="form-grid"><label>Clave censurada<select id="pulse-key" class="select">${data.cloud.keys.map((key) => `<option value="${esc(key.id)}">${esc(key.name)} · ${esc(key.maskedToken)}</option>`).join('')}</select></label></div>`, `<div class="form-actions"><button class="button subtle" data-close-modal>Cancelar</button><button class="button primary" id="pulse-confirm">Iniciar Pulse</button></div>`);
      await new Promise((resolve) => { $('pulse-confirm').onclick = () => { keyId = $('pulse-key').value; $('modal-root').replaceChildren(); resolve(); }; });
    } else keyId = data.cloud.keys[0].id;
  }
  try {
    const created = await api('/api/scans', { method: 'POST', body: JSON.stringify({ repo, prNumber, mode, keyId }) });
    state.selectedScan = created.id; state.readOnlyEvidence = false;
    if (created.updatedExisting) toast('Se actualiza el expediente de esta PR y modo; la versión anterior queda en el historial forense.');
    go('evidence'); $('evidence-selection').textContent = `${repo} / PR #${prNumber} / ${mode.toUpperCase()}`;
    $('evidence-content').innerHTML = `<article class="scan-progress scanning"><div class="scan-visual"><span class="scan-orb"><i></i><i></i><i></i></span><div class="scan-wave"><i></i><i></i><i></i><i></i><i></i></div></div><div class="scan-progress-body"><div class="scan-progress-head"><div><span class="eyebrow">${modeLabel} · ANÁLISIS ACTIVO</span><strong>Analizando ${esc(repo)} · PR #${prNumber}</strong></div><span id="scan-stage-count">0 etapas</span></div><div class="scan-progress-track"><i></i></div><p>La ruta se construye con las etapas que el servidor confirma; no se estima un porcentaje de finalización.</p></div></article><div id="live-route" class="live-route" aria-live="polite"></div>`;
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
      if (data.status === 'COMPLETE' && data.result) { state.selectedScan = id; state.readOnlyEvidence = false; renderEvidence(data.result); loadRecent(); return; }
      if (data.status === 'FAILED') { $('evidence-content').innerHTML += `<div class="finding-card sev-high"><h4>Escaneo incompleto</h4><p>${esc(data.error)}</p><div class="form-actions"><button type="button" class="button subtle" id="scan-back">← Volver a repositorios</button></div></div>`; if ($('scan-back')) $('scan-back').onclick = goBack; return; }
      await new Promise((resolve) => setTimeout(resolve, 1100));
    } catch (error) { toast(`Se perdió la consulta de progreso: ${error.message}`); return; }
  }
}
async function beginToolInstall(tool, trigger) {
  if (!installableTools.has(tool)) return toast(`El instalador integrado no cubre ${tool}.`);
  if (trigger) { trigger.disabled = true; trigger.dataset.label = trigger.textContent; trigger.textContent = 'Abriendo instalador…'; setTimeout(() => { trigger.disabled = false; trigger.textContent = trigger.dataset.label || 'Descargar e instalar'; }, 500); }
  const terms=tool==='codeql';
  const body=`<div class="install-confirm"><p>Se instalará en <code>%USERPROFILE%\\.sentinel-audit\\tools</code>, separado de otras aplicaciones. No requiere privilegios de administrador.</p><p>El instalador obtiene versiones oficiales y verifica SHA-256 cuando el proveedor publica un digest. Las herramientas Python usan un entorno virtual aislado y solo ruedas binarias.</p>${terms?'<label class="check-row"><input id="codeql-terms" type="checkbox"> Confirmo que el uso de CodeQL se limita a código abierto elegible o investigación académica, según sus términos.</label><p><a href="https://github.com/github/codeql-cli-binaries#terms-and-conditions" target="_blank" rel="noreferrer">Términos oficiales de CodeQL</a></p>':''}<div class="install-job" id="install-job"></div><div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cancelar</button><button type="button" class="button primary" id="install-confirm" ${terms?'disabled':''}>Iniciar instalación</button></div></div>`;
  showModal(`Instalar ${tool}`,body);
  if(terms)$('codeql-terms').addEventListener('change',(event)=>{$('install-confirm').disabled=!event.target.checked;});
  $('install-confirm').addEventListener('click',async(event)=>{const button=event.currentTarget;button.disabled=true;button.textContent='Instalando…';const box=$('install-job');if(box)box.innerHTML='<div class="install-status"><strong>PREPARANDO</strong><span>Solicitando instalación…</span><progress max="100" value="0"></progress><small>0%</small></div>';try{const job=await api('/api/tools/install',{method:'POST',body:JSON.stringify({tool,acceptLicenseTerms:terms&&$('codeql-terms').checked})});await pollToolInstall(job.id);}catch(error){if($('install-job'))$('install-job').innerHTML=`<p class="install-error">${esc(error.message)}</p>`;button.disabled=false;button.textContent='Reintentar instalación';}});
}
async function pollToolInstall(id) {
  const root = $('modal-root');
  if (root) root.dataset.installJob = id;
  for (;;) {
    try {
      const job = await api(`/api/tools/jobs/${encodeURIComponent(id)}`);
      const box = $('install-job');
      if (!box) return;
      if (job.state === 'AVAILABLE' || job.state === 'BLOCKED') {
        const blocked = job.state === 'BLOCKED';
        box.innerHTML = `<div class="${blocked ? 'install-status' : 'install-success'}"><span class="install-check" aria-hidden="true"></span><div><strong>${blocked ? 'Descarga completada · ejecución bloqueada' : 'Instalación completada'}</strong><span>${esc(job.message || `${job.tool} está disponible.`)}</span></div><progress max="100" value="100"></progress><small>100%</small></div>`;
        const modal = box.closest('.modal'); if (modal && !blocked) modal.classList.add('modal-success');
        const action = $('install-confirm'); if (action) { action.textContent = blocked ? 'Descargado, bloqueado por el host' : 'Instalación completada'; action.disabled = true; }
        await loadState();
        toast(blocked ? job.message || `${job.tool} está instalado pero bloqueado por el host.` : job.message || `${job.tool} instalado.`);
        if (!blocked) setTimeout(() => { if (box.isConnected && root && root.dataset.installJob === id) root.replaceChildren(); }, 1700);
        return;
      }
      box.innerHTML = `<div class="install-status"><strong>${esc(job.state)}</strong><span>${esc(job.message || '')}</span><progress max="100" value="${Number(job.percent) || 0}"></progress><small>${Number(job.percent) || 0}%</small>${job.error ? `<p class="install-error">${esc(job.error)}</p>` : ''}</div>`;
      if (job.state === 'FAILED') { const action = $('install-confirm'); if (action) { action.disabled = false; action.textContent = 'Reintentar instalación'; } return; }
      await new Promise((resolve) => setTimeout(resolve, 700));
    } catch (error) {
      const box = $('install-job'); if (box) box.innerHTML = `<p class="install-error">${esc(error.message)}</p>`;
      const action = $('install-confirm'); if (action) { action.disabled = false; action.textContent = 'Reintentar instalación'; }
      return;
    }
  }
}
function renderEvidence(body) {
  window.__currentEvidenceBody = body;
  const audit = body.audit || {}; const stages = audit.stages || {}; const tools = audit.tools || {};
  const timeline = Array.isArray(body.stageTimeline) ? body.stageTimeline : [];
  const eventByStage = new Map();
  for (const event of timeline) if (event && event.stage) eventByStage.set(event.stage, event);
  const statusFor = (value) => {
    const s = String(value || '').toUpperCase();
    if (/FAILED|ERROR|TIMEOUT/.test(s)) return 'failed';
    if (/COMPLETE|CLEAN|SUCCESS/.test(s)) return 'complete';
    if (/RUNNING|STARTED/.test(s)) return 'running';
    if (/NOT_RUN|NOT_RECORDED|NOT_APPLICABLE|PLANNED|SKIP|UNAVAILABLE|INVALID/.test(s)) return 'omitted';
    return 'partial';
  };
  const statusLabel = { complete: 'COMPLETO', failed: 'FALLÓ', running: 'EN CURSO', omitted: 'NO EJECUTADO', partial: 'PARCIAL' };
  const detailText = (value) => {
    if (value == null) return 'Sin detalle registrado';
    if (typeof value === 'string') return value;
    if (typeof value === 'object') return Object.entries(value).map(([key, item]) => `${key}: ${typeof item === 'string' ? item : JSON.stringify(item)}`).join(' · ');
    return String(value);
  };
  const routeStep = (index, label, status, detail) => `<article class="route-step ${status}"><span class="route-index">${String(index).padStart(2, '0')}</span><div class="route-copy"><strong>${esc(label)}</strong><small>${esc(detail)}</small></div><span class="route-chip">${statusLabel[status] || 'PARCIAL'}</span></article>`;
  const definitions = [
    ['PR_METADATA', 'Identidad del PR'], ['DIFF_PIN', 'Diff fijado · SHA-256'], ['SENTINEL_LITE', 'Lite · referencia del diff'],
    ['PREFLIGHT', 'Preflight de cobertura'], ['IDENTITY', 'Checkout fijado por commit'], ['ENGINE', 'Motor principal'],
    ['ROUTING', 'Enrutamiento de señales'], ['SPECIALISTS', 'Herramientas especialistas'], ['CORRELATION', 'Correlación de evidencia'],
    ['TRIAGE', 'Triage y veredicto'], ['CLEANUP', 'Limpieza del entorno']
  ];
  const nodes = definitions.map(([key, label], index) => {
    const event = eventByStage.get(key); const stage = stages[key];
    const rawStatus = event && event.state || stage && stage.state || (key === 'SENTINEL_LITE' ? 'COMPLETE' : 'NOT_RECORDED');
    let detail = event ? detailText(event.detail) : stage ? detailText(stage.detail || stage.state) : key === 'SENTINEL_LITE' ? `${body.lite && body.lite.findings ? body.lite.findings.length : 0} señales Lite; referencia local del diff` : 'No se registró un evento para esta etapa';
    if (key === 'SENTINEL_LITE' && body.mode !== 'lite') detail = `Referencia paralela · ${body.lite && body.lite.findings ? body.lite.findings.length : 0} señales; no origina el enrutamiento`;
    if (key === 'ENGINE') detail = `${(body.analysisProvenance && body.analysisProvenance.primary && body.analysisProvenance.primary.label) || (body.mode === 'pulse' ? 'Sentinel Cloud · Pulse' : body.mode === 'local' ? 'Motor Sentinel local completo' : 'Sentinel Audit Lite')} · ${body.analysisProvenance && Number(body.analysisProvenance.primarySignalCount) || 0} señales normalizadas`;
    if (key === 'PREFLIGHT' && !event && audit.preflight) detail = detailText(audit.preflight.verdict || audit.preflight);
    if (key === 'CLEANUP' && !event && audit.cleanup) detail = detailText(audit.cleanup.cleanupStatus || audit.cleanup);
    return routeStep(index + 1, label, statusFor(rawStatus), detail);
  }).join('');
  const provenance = body.analysisProvenance || {};
  const primary = provenance.primary || { label: body.mode === 'pulse' ? 'Sentinel Cloud · Pulse' : body.mode === 'local' ? 'Motor Sentinel local completo' : 'Sentinel Audit Lite · diff del PR' };
  const routed = Array.isArray(provenance.routedByPrimarySignals) ? provenance.routedByPrimarySignals : (audit.signalRouting && audit.signalRouting.tools || []);
  const independent = Array.isArray(provenance.independentChecks) ? provenance.independentChecks : [];
  const provenanceHtml = `<section class="provenance-card"><div class="provenance-head"><div><p class="eyebrow">ORIGEN Y FLUJO DE SEÑALES</p><h3>${esc(primary.label)}</h3></div><span class="badge">${Number(provenance.primarySignalCount) || 0} señales normalizadas</span></div><p>${esc(provenance.flow || 'El motor principal genera la evidencia que se enruta a las herramientas especialistas.')}</p><div class="provenance-flow"><div class="provenance-node"><small>1 · FUENTE PRINCIPAL</small><strong>${esc(primary.label)}</strong><span>${esc(primary.scope || 'Checkout del commit fijado por SHA')}</span></div><i aria-hidden="true">→</i><div class="provenance-node"><small>2 · ENRUTAMIENTO POR SEÑALES</small><strong>${esc(routed.join(', ') || 'Sin especialista dirigido')}</strong><span>${esc(provenance.routingReason || 'Herramientas elegidas por las señales normalizadas del motor principal.')}</span></div><i aria-hidden="true">→</i><div class="provenance-node"><small>3 · CORROBORACIÓN</small><strong>${esc(independent.map((check) => check.tool).join(', ') || 'Especialistas dirigidos')}</strong><span>Los resultados se correlacionan y quedan asociados a su motor fuente.</span></div></div>${provenance.liteReference ? `<div class="provenance-reference"><span>LITE EN PARALELO</span><strong>${esc(provenance.liteReference.label)}</strong><code>SHA-256 ${esc(provenance.liteReference.sha256 || body.diff.sha256)}</code><small>${esc(provenance.liteReference.role)}</small></div>` : ''}</section>`;
  const specialistNodes = Object.entries(tools).filter(([name]) => name !== 'sentinel').map(([name, item], index) => {
    const independentCheck = independent.some((check) => check.tool === name);
    const status = ({ SUCCESS: 'complete', COMPLETE: 'complete', ERROR: 'failed', FAILED: 'failed', TIMEOUT: 'failed', UNAVAILABLE: 'omitted', SKIPPED: 'omitted', NOT_RUN: 'omitted', NOT_APPLICABLE: 'omitted', INVALID: 'omitted' })[String(item.status || '').toUpperCase()] || 'partial';
    return `<article class="specialist-branch ${status}"><span class="branch-junction">${independentCheck ? '↳' : '└'}</span><div><strong>${esc(name)}</strong><small>${independentCheck ? 'COMPROBACIÓN INDEPENDIENTE' : 'ENRUTADA DESDE EL MOTOR PRINCIPAL'} · ${esc(item.status || 'NOT RUN')} · ${Number(item.findingCount) || (item.findings || []).length || 0} señales</small></div><span class="route-chip">${statusLabel[status]}</span></article>`;
  }).join('');
  const findings = [...(body.lite && body.lite.findings || []).map((item) => ({...item, source:'Sentinel Lite'})), ...Object.entries(tools).flatMap(([source, item]) => (item.findings || []).map((finding) => ({...finding, source})))].map((finding) => ({ ...finding, __title: findingTitle(finding), __severity: displaySeverity(finding) }));
  const unique = new Map(); for (const finding of findings) unique.set(`${findingSource(finding)}|${findingFile(finding)}|${findingLine(finding)}|${finding.__title}`, finding);
  const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const evidenceFindings = [...unique.values()].sort((a, b) => (severityOrder[b.__severity] || 0) - (severityOrder[a.__severity] || 0));
  const candidates = Array.isArray(audit.candidates) ? audit.candidates : [];
  const observations = Array.isArray(audit.observations) ? audit.observations : [];
  const natureHtml = renderSignalNature(evidenceFindings);
  const candidateCards = candidates.map((candidate, index) => renderCandidateCard(candidate, index)).join('');
  const candidateSection = `<section class="candidate-section"><div class="analysis-section-title"><h3>Candidatos correlacionados</h3><span>${candidates.length} · verificación humana pendiente</span></div>${candidateCards || '<div class="empty-state">No hay candidatos corroborados por las autoridades de código configuradas.</div>'}${observations.length ? `<details class="observation-list"><summary>${observations.length} observaciones que no son candidatos</summary>${observations.slice(0,100).map((item,index)=>renderObservation(item,body,index)).join('')}</details>` : ''}</section>`;
  window.__evidenceCandidates = candidates;
  window.__evidenceTriageRuns = Array.isArray(audit.triageRuns) ? audit.triageRuns : [];
  window.__evidenceFindings = evidenceFindings;
  const findingHtml = evidenceFindings.map((f, index) => {
    const severity = f.__severity; const file = evidencePath(findingFile(f)) || 'ubicación desconocida'; const line = findingLine(f); const snippet = findingSnippet(f); const detail = findingDetail(f); const nature = classifySignalNature(f);
    return `<article class="finding-card sev-${esc(String(severity).toLowerCase())}"><div class="finding-head"><div class="finding-title"><span class="severity-pill sev-${esc(String(severity).toLowerCase())}">${esc(severity)}</span><h4>${esc(f.__title)}</h4></div><span class="finding-source">${esc(findingSource(f))}</span></div>${detail ? `<p>${esc(detail)}</p>` : ''}<div class="finding-meta"><code>${esc(file)}${line ? `:${line}` : ''}</code><span class="badge">${esc(f.category || f.kind || 'sin categoría')}</span><span class="badge nature-${nature.id}">${esc(nature.short)}</span></div>${snippet ? `<pre class="finding-snippet">${esc(snippet)}</pre>` : ''}<div class="finding-actions"><button type="button" class="button subtle small" data-finding="${index}">Ver evidencia completa</button>${githubEvidenceLink(body,findingFile(f),line)}</div></article>`;
  }).join('');
  const verdict = audit.auditVerdict && audit.auditVerdict.verdict || body.lite.verdict;
  const missing = Object.entries(tools).filter(([, t]) => ['UNAVAILABLE','ERROR','TIMEOUT','SKIPPED','INVALID'].includes(t.status)).map(([name]) => name);
  const noFindingState = evidenceFindings.length === 0 && candidates.length === 0 && observations.length === 0;
  const completedTools = Object.entries(tools).filter(([, tool]) => ['SUCCESS','COMPLETE'].includes(String(tool.status || '').toUpperCase())).map(([name]) => name);
  const noFindingsHtml = noFindingState ? `<section class="no-findings-card ${missing.length ? 'coverage-limited' : ''}"><div class="no-findings-mark">0</div><div><p class="eyebrow">RESULTADO DEL ANÁLISIS</p><h3>${missing.length ? 'No se observaron hallazgos · cobertura limitada' : 'No se observaron hallazgos en las etapas registradas'}</h3><p>PR #${esc(body.pullRequest.number)} · ${esc(body.repository)} · commit ${esc(String(body.pullRequest.commit || '').slice(0,12))}. Motores completos: ${esc(completedTools.join(', ') || (body.mode === 'lite' ? 'Sentinel Audit Lite' : 'motor principal registrado'))}.</p><small>Un resultado sin hallazgos describe únicamente las herramientas y el alcance que se ejecutaron; no prueba que el cambio esté libre de vulnerabilidades.${missing.length ? ` Especialistas con cobertura pendiente: ${esc(missing.join(', '))}.` : ''}</small></div></section>` : '';
  $('evidence-selection').textContent = `${body.repository} / PR #${body.pullRequest.number} / ${body.mode.toUpperCase()}${state.readOnlyEvidence ? ' / REVISIÓN HISTÓRICA' : ''}`;
  const routeGraph = `<div class="route-map">${nodes}<div class="specialist-branches">${specialistNodes || '<div class="route-empty-branch">Sin resultados de especialistas registrados.</div>'}</div></div>`;
  $('evidence-content').innerHTML = `<div class="evidence-layout"><div><article class="glass-card"><p class="eyebrow">AUDIT PIPELINE / ${esc(audit.auditVerdict && audit.auditVerdict.analysisState || 'PARTIAL')}</p><h2>${esc(verdict)}</h2><p>${esc(audit.auditVerdict && audit.auditVerdict.statement || 'El resultado requiere revisión humana y se limita a la cobertura registrada.')}</p><div class="finding-card verdict-card ${body.lite.verdict === 'BLOCK' ? 'sev-critical' : body.lite.verdict === 'REVIEW' ? 'sev-medium' : ''}"><h4>Lite · ${body.mode === 'lite' ? 'motor de entrada' : 'referencia paralela'} · ${esc(body.lite.verdict)} <span class="badge ${body.lite.verdict === 'BLOCK' ? 'danger' : ''}">RIESGO ${body.lite.riskScore}/100</span></h4><p>${body.lite.counts.critical} críticas · ${body.lite.counts.high} altas · ${body.lite.counts.medium} medias · ${body.lite.counts.low} bajas. Este veredicto pertenece al análisis del diff; el estado del pipeline y la cobertura se muestran por separado.</p></div><aside class="intent-note"><strong>Intención del autor: no inferida</strong><p>Sentinel separa indicadores de comportamiento malicioso de defectos de seguridad, pero un hallazgo por sí solo no demuestra dolo ni permite distinguir con certeza entre un error del desarrollador y una acción intencional. Esa conclusión requiere contexto y revisión humana.</p></aside>${natureHtml}</article>${provenanceHtml}<article class="map-card" style="margin-top:13px"><div class="route-head"><div><p class="eyebrow">EVIDENCE ROUTE</p><h3>Cadena de custodia por etapa</h3></div><div class="route-legend"><span class="complete">COMPLETO</span><span class="partial">PARCIAL</span><span class="failed">FALLÓ</span><span class="omitted">NO EJECUTADO</span></div></div>${routeGraph}</article>${candidateSection}<div class="analysis-section-title"><h3>Señales individuales</h3><span>${evidenceFindings.length} registros recibidos</span></div><div class="finding-list">${findingHtml || noFindingsHtml || '<div class="empty-state">No hay una conclusión completa. Consulta la ruta y los estados de cada motor.</div>'}</div></div><aside class="glass-card"><p class="eyebrow">IMMUTABLE REFERENCES</p><div class="hash-line"><strong>RESULT BODY SHA-256</strong><br>${esc(body.integrity.bodyHash)}</div><div class="hash-line" style="margin-top:14px"><strong>DIFF SHA-256</strong><br>${esc(body.diff.sha256)}</div><div class="hash-line" style="margin-top:14px"><strong>PINNED COMMIT</strong><br>${esc(body.pullRequest.commit)}</div><button class="button subtle" id="show-json" style="margin-top:15px;width:100%">Ver cuerpo JSON</button><button class="button subtle" id="download-json" style="margin-top:8px;width:100%">Descargar JSON</button><button class="button subtle" id="download-sarif" style="margin-top:8px;width:100%">Descargar SARIF</button><p class="eyebrow" style="margin-top:22px">TOOL COVERAGE GAPS</p><p class="muted">${missing.length ? `No completadas: ${esc(missing.join(', '))}` : 'Sin estados de especialista pendientes.'}</p>${missing.length && !state.readOnlyEvidence ? `<button class="button" id="extend-scan" style="width:100%">Reintentar especialistas dirigidos</button><p class="muted">Solo herramientas justificadas por la ruta guardada. Las no seleccionadas por evidencia no se fuerzan.</p>` : state.readOnlyEvidence ? '<p class="muted">Revisión histórica de solo lectura.</p>' : ''}</aside></div>`;
  $('show-json').onclick = () => showModal('Cuerpo JSON del escaneo', `<pre>${esc(JSON.stringify(body, null, 2))}</pre>`);
  $('download-json').onclick = () => { const blob = new Blob([JSON.stringify(body, null, 2)], {type:'application/json'}); const url=URL.createObjectURL(blob); const a=document.createElement('a');a.href=url;a.download=`sentinel-audit-${body.repository.replace('/','-')}-pr-${body.pullRequest.number}.json`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),2000); };
  if (body.mode === 'local' || body.mode === 'pulse') { const engineBodyButton = document.createElement('button'); engineBodyButton.type = 'button'; engineBodyButton.id = 'show-engine-body'; engineBodyButton.className = 'button subtle'; engineBodyButton.style.cssText = 'margin-top:8px;width:100%'; engineBodyButton.textContent = body.mode === 'pulse' ? 'Ver cuerpo crudo de Pulse' : 'Ver cuerpo crudo del motor local'; engineBodyButton.onclick = showPrimaryEngineBody; $('download-json').insertAdjacentElement('afterend', engineBodyButton); }
  $('download-sarif').onclick = () => downloadSarif(body, evidenceFindings);
  document.querySelectorAll('[data-finding]').forEach((button) => button.addEventListener('click', () => showFindingEvidence(window.__evidenceFindings[Number(button.dataset.finding)])));
  document.querySelectorAll('[data-candidate]').forEach((card) => {
    const open = () => showCandidateEvidence(window.__evidenceCandidates[Number(card.dataset.candidate)]);
    card.addEventListener('click', open);
    card.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
  });
  if ($('extend-scan') && !state.readOnlyEvidence) $('extend-scan').onclick = async () => {
    try { const updated = await api(`/api/scans/${encodeURIComponent(state.selectedScan)}/extend`, {method:'POST', body:JSON.stringify({tools:[]})}); renderEvidence(updated.result); toast('La ruta de especialistas se actualizó.'); }
    catch (error) { toast(`No se pudo ampliar el análisis: ${error.message}`); }
  };
}
function downloadSarif(body, findings) {
  const rules = new Map();
  const results = findings.map((finding) => {
    const ruleId = String(ruleLabel(finding) || findingTitle(finding)).slice(0, 300);
    if (!rules.has(ruleId)) rules.set(ruleId, { id: ruleId, name: ruleId, shortDescription: { text: ruleId } });
    const file = evidencePath(findingFile(finding)); const line = findingLine(finding);
    const severity = displaySeverity(finding);
    const level = severity === 'CRITICAL' || severity === 'HIGH' ? 'error' : severity === 'MEDIUM' ? 'warning' : 'note';
    const result = { ruleId, level, message: { text: findingDetail(finding) || findingTitle(finding) }, properties: { severity, source: findingSource(finding), evidence: finding } };
    if (file) result.locations = [{ physicalLocation: { artifactLocation: { uri: file.split('/').map(encodeURIComponent).join('/') }, ...(line ? { region: { startLine: line } } : {}) } }];
    return result;
  });
  const sarif = { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{ tool: { driver: { name: 'Sentinel Audit', informationUri: 'https://github.com/', rules: [...rules.values()] } }, results, properties: { repository: body.repository, pullRequest: body.pullRequest.number, commitSha: body.pullRequest.commit, diffSha256: body.diff.sha256, bodySha256: body.integrity.bodyHash } }] };
  const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/sarif+json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `sentinel-audit-${String(body.repository).replace('/', '-')}-pr-${body.pullRequest.number}.sarif`; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function showCandidateEvidence(candidate) {
  if (!candidate) return;
  const signals = candidate.signals || candidate.evidence || [];
  const triage = (window.__evidenceTriageRuns || []).find((entry) => entry.candidateId === candidate.candidateId);
  const legacyAdjudication = triage && ['CONFIRMED','FALSE_POSITIVE'].includes(String(triage.verdict || '').toUpperCase());
  const triageBadge = legacyAdjudication ? 'HISTÓRICO · NO VALIDADO' : triage && triage.verdict || 'UNKNOWN';
  const triageReason = legacyAdjudication ? 'Este registro viene de una versión anterior que usaba heurísticas para adjudicar. No se considera una confirmación ni un descarte; vuelve a verificar el candidato.' : triage && triage.reason || 'Sin conclusión automática.';
  const triagePanel = triage ? `<article class="candidate-detail"><div class="signal-card-head"><strong>Seguimiento heurístico local</strong><span class="badge warn">${esc(triageBadge)}</span></div><p class="signal-detail">${esc(triageReason)}</p>${triage.heuristicProbe ? `<div class="evidence-list-row"><span>Resultado auxiliar</span><strong>${esc(triage.heuristicProbe.outcome || '—')}</strong></div><p class="candidate-caveat">${esc(triage.heuristicProbe.limitation || 'No confirma ni descarta una vulnerabilidad.')}</p>` : ''}</article>` : '';  const rows = [['ID', candidate.candidateId], ['Estado', candidate.status || candidate.verificationStatus || 'MANUAL_VERIFICATION_REQUIRED'], ['Disposición', candidate.disposition || 'PLAUSIBLE_SECURITY_ISSUE'], ['Corroboración', candidate.confidence || '—'], ['Autoridades', (candidate.corroboratingAuthorities || candidate.tools || []).join(', ') || '—'], ['Archivo', `${evidencePath(candidate.file) || '—'}${candidate.line ? `:${candidate.line}` : ''}`], ['Asociación Cloud', candidate.cloudAssociationScope || '—']];
  const signalCards = signals.map((signal, index) => `<article class="signal-evidence"><div class="signal-card-head"><strong>${esc(signal.tool || signal.authority || `Señal ${index+1}`)}</strong><span class="badge">${esc(signal.rule || signal.signalClass || 'sin regla')}</span></div><p class="signal-detail">${esc(signal.detail || signal.verdictFromTool || 'El motor no agregó una descripción textual.')}</p>${renderSignalFlow(signal)}${githubEvidenceLink(window.__currentEvidenceBody,signal.file || signal.path || (signal.location && signal.location.path) || candidate.file,signal.line || (signal.location && signal.location.line) || candidate.line)}${signal.controls && signal.controls.length ? `<div class="evidence-list-row"><span>Controles</span><strong>${esc(evidenceText(signal.controls))}</strong></div>` : ''}${signal.blockedBy && signal.blockedBy.length ? `<div class="evidence-list-row"><span>Mitigado por</span><strong>${esc(evidenceText(signal.blockedBy))}</strong></div>` : ''}${signal.snippet ? `<pre class="finding-snippet">${esc(signal.snippet)}</pre>` : ''}<details><summary>JSON de la señal</summary><pre class="evidence-json">${esc(JSON.stringify(signal, null, 2))}</pre></details></article>`).join('');
  const candidateLink = githubEvidenceLink(window.__currentEvidenceBody,candidate.file || candidate.path,candidate.line || candidate.startLine);
  showModal(`Expediente ${candidate.candidateId || 'de candidato'}`, `<div class="candidate-detail"><p>${esc(candidate.note || 'La correlación indica coincidencia de señales; no determina explotabilidad.')}</p>${rows.map(([label,value])=>`<div class="evidence-list-row"><span>${esc(label)}</span><strong>${esc(evidenceText(value) || '—')}</strong></div>`).join('')}${candidateLink}<p class="candidate-caveat">El nivel de corroboración cuenta autoridades independientes según la política. No representa probabilidad de explotación ni confirmación de vulnerabilidad.</p>${triagePanel}<h4>Señales fuente · ${signals.length}</h4><div class="signal-list">${signalCards || '<p class="flow-empty">El expediente no contiene señales normalizadas.</p>'}</div><details><summary>JSON del candidato</summary><pre class="evidence-json">${esc(JSON.stringify(candidate, null, 2))}</pre></details></div>`, '<div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cerrar</button></div>');
}
function showFindingEvidence(finding) {
  if (!finding) return;
  const file = evidencePath(findingFile(finding)) || '—';
  const line = findingLine(finding);
  const rows = [['Título', findingTitle(finding)], ['Severidad', displaySeverity(finding)], ['Naturaleza', classifySignalNature(finding).label], ['Fuente', findingSource(finding)], ['Categoría', finding.category || finding.kind || '—'], ['Archivo', line ? `${file}:${line}` : file]];
  showModal('Evidencia del hallazgo', `<div class="evidence-detail">${rows.map(([label, value]) => `<div class="evidence-detail-row"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('')}${githubEvidenceLink(window.__currentEvidenceBody,findingFile(finding),line)}${findingSnippet(finding) ? `<pre class="finding-snippet">${esc(findingSnippet(finding))}</pre>` : ''}<p class="eyebrow">OBJETO NORMALIZADO</p><pre class="evidence-json">${esc(JSON.stringify(finding, null, 2))}</pre></div>`, '<div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cerrar</button></div>');
}
async function showPrimaryEngineBody() {
  if (!state.selectedScan) return toast('Selecciona un expediente antes de abrir el cuerpo del motor.');
  try {
    const artifact = await api(`/api/scans/${encodeURIComponent(state.selectedScan)}/engine-body`);
    const json = JSON.stringify(artifact.body, null, 2);
    showModal(`${artifact.engine} · cuerpo crudo`, `<div class="engine-body-meta"><span>${esc(artifact.mode.toUpperCase())} · ${esc(artifact.status)}</span><code>${esc(artifact.artifact)}</code><code>SHA-256 ${esc(artifact.sha256)}</code><p>Artefacto del motor principal, anterior a la normalización y al enrutamiento. No incluye los resultados consolidados de especialistas.</p><pre class="evidence-json">${esc(json)}</pre></div>`, '<div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cerrar</button><button type="button" class="button primary" id="download-engine-body">Descargar cuerpo JSON</button></div>');
    $('download-engine-body').onclick = () => { const blob = new Blob([json], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `sentinel-${artifact.mode}-engine-body-${state.selectedScan}.json`; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000); };
  } catch (error) { toast(`No se pudo abrir el cuerpo crudo: ${error.message}`); }
}
async function loadRecent() {
  try { const { scans } = await api('/api/scans'); $('recent-scans').innerHTML = scans.length ? scans.slice(0,8).map((scan) => `<div class="recent-row"><div class="recent-main"><strong>${esc(scan.repo)} #${scan.pr_number} · ${esc(scan.verdict || scan.status)}</strong><small>${esc(scan.mode)} · ${esc(scan.started_at)} · ${scan.finding_count} registros</small></div><div class="recent-actions"><span class="badge ${scan.status === 'FAILED' ? 'danger' : ''}">${esc(scan.status)}</span><button class="button subtle small" type="button" data-open-scan="${esc(scan.id)}">Ver resultados</button></div></div>`).join('') : '<div class="empty-state">Todavía no hay escaneos guardados.</div>'; document.querySelectorAll('[data-open-scan]').forEach((row) => row.addEventListener('click', () => openScan(row.dataset.openScan))); }
  catch (error) { $('recent-scans').innerHTML = `<div class="empty-state">${esc(error.message)}</div>`; }
}
async function openScan(id) { try { const scan = await api(`/api/scans/${encodeURIComponent(id)}`); if (scan.result) { state.selectedScan=id; state.readOnlyEvidence=!!scan.historical; go('evidence'); renderEvidence(scan.result); } } catch (error) { toast(error.message); } }
async function searchForensics() {
  const names = ['q','sha','repo','pr','mode','engine','severity'];
  const params = new URLSearchParams();
  for (const name of names) { const input = $(`forensic-${name}`); if (input && input.value.trim()) params.set(name, input.value.trim()); }
  const summary = $('forensic-summary'); const results = $('forensic-results');
  if (!summary || !results) return;
  summary.textContent = 'Buscando en expedientes actuales y revisiones archivadas…'; results.innerHTML = '';
  try {
    const data = await api(`/api/forensics?${params.toString()}`);
    const rows = data.results || [];
    summary.textContent = `${rows.length} expediente(s) · máximo 200 · SHA de commit, diff y cuerpo indexados`;
    results.innerHTML = rows.length ? rows.map((row) => `<article class="forensic-result"><div class="forensic-result-head"><div><span class="record-type ${row.record_type === 'HISTORICAL' ? 'historical' : ''}">${row.record_type === 'HISTORICAL' ? 'REVISIÓN ARCHIVADA' : 'ACTUAL'}</span><h3>${esc(row.repo)} · PR #${esc(row.pr_number)}</h3></div><span class="badge ${row.status === 'FAILED' ? 'danger' : ''}">${esc(row.status)}</span></div><div class="forensic-meta"><span>${esc(row.mode.toUpperCase())}</span><span>${esc(row.verdict || 'SIN VEREDICTO')}</span><span>${Number(row.finding_count) || 0} señales</span><time>${esc(row.started_at || '')}</time></div><div class="forensic-hashes"><div><small>COMMIT</small><code>${esc(row.head_sha || '—')}</code></div><div><small>DIFF SHA-256</small><code>${esc(row.diff_sha256 || '—')}</code></div><div><small>EXPEDIENTE SHA-256</small><code>${esc(row.body_sha256 || '—')}</code></div></div><button class="button subtle small" type="button" data-open-forensic="${esc(row.result_id)}">Abrir expediente</button></article>`).join('') : '<div class="empty-state">No hay expedientes que coincidan con esos filtros.</div>';
    results.querySelectorAll('[data-open-forensic]').forEach((button) => button.addEventListener('click', () => openScan(button.dataset.openForensic)));
  } catch (error) { summary.textContent = `Búsqueda fallida: ${error.message}`; results.innerHTML = ''; }
}
if ($('forensic-form')) $('forensic-form').addEventListener('submit', (event) => { event.preventDefault(); searchForensics(); });
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
function fileRanking(rows) {
  const max = Math.max(1, ...rows.map((row) => Number(row.count) || 0));
  return `<article class="analytics-card"><div class="analytics-card-head"><div><h3>Archivos con más hallazgos</h3><p class="muted">Mapa de la superficie que más se está tocando en los diffs.</p></div></div>${rows.length ? `<ol class="file-ranking">${rows.map((row) => `<li><div class="file-rank-main"><code>${esc(row.file || 'Sin ruta')}</code><small>${Number(row.count) || 0} hallazgo(s)</small></div><div class="file-rank-bar"><i style="width:${Math.max(4, (Number(row.count) || 0) / max * 100)}%"></i></div><button type="button" class="button subtle small" data-history-file="${esc(row.file || '')}">Ver historial</button></li>`).join('')}</ol>` : '<p class="muted">Sin datos de archivo.</p>'}</article>`;
}
function categoryTiles(rows) {
  const max = Math.max(1, ...rows.map((r) => Number(r.count) || 0));
  return `<article class="analytics-card"><div class="analytics-card-head"><div><h3>Tipos de señal</h3><p class="muted">Categorías tácticas detectadas y su peso histórico.</p></div></div><div class="category-tiles">${rows.length ? rows.map((row) => `<div class="category-tile" style="--tile-weight:${Math.max(1, Number(row.count) || 0) / max}"><div class="category-main"><span>${esc(row.category || 'Sin categoría')}</span><strong>${Number(row.count) || 0}</strong></div><div class="category-meter"><i></i></div><button type="button" class="button subtle small" data-history-category="${esc(row.category || '__none__')}">Ver historial</button></div>`).join('') : '<p class="muted">Sin categorías.</p>'}</div></article>`;
}
async function showHistory(params) {
  const label = params.category === '__none__' ? 'Sin categoría' : (params.category || params.file || 'Historial');
  showModal(`Historial · ${label}`, '<div id="history-body"><div class="empty-state">Consultando expedientes…</div></div>', '<div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cerrar</button></div>');
  try {
    const data = await api(`/api/findings?${new URLSearchParams(params).toString()}`);
    const rows = (data.rows || []).map((row) => {
      let evidence = {}; try { evidence = JSON.parse(row.evidence || '{}'); } catch (_) {}
      const merged = { ...evidence, severity: row.severity, category: row.category, file: row.file, line: row.line, source: row.source, title: row.title };
      const severity = displaySeverity(merged);
      return `<div class="history-row"><div class="history-main"><div class="history-top"><span class="severity-pill sev-${esc(String(severity).toLowerCase())}">${esc(severity)}</span><strong>${esc(findingTitle(merged))}</strong></div><small>${esc(row.repo)} #${row.pr_number} · ${esc(row.mode)} · ${esc(String(row.started_at || '').slice(0, 10))}</small><code>${esc(evidencePath(row.file) || '—')}${row.line ? `:${row.line}` : ''}</code></div><button type="button" class="button subtle small" data-history-scan="${esc(row.scan_id)}">Ver escaneo</button></div>`;
    }).join('');
    const body = $('history-body'); if (!body) return;
    body.innerHTML = rows ? `<div class="history-list">${rows}</div><p class="muted">${data.rows.length} registro(s) · máximo 300</p>` : '<div class="empty-state">Todavía no hay hallazgos registrados para este filtro.</div>';
    body.querySelectorAll('[data-history-scan]').forEach((button) => button.addEventListener('click', () => { $('modal-root').replaceChildren(); openScan(button.dataset.historyScan); }));
  } catch (error) { const body = $('history-body'); if (body) body.innerHTML = `<div class="empty-state">${esc(error.message)}</div>`; }
}
function timelineSvg(rows) { const width=640,height=180,pad=28,max=Math.max(1,...rows.map(r=>Number(r.count)||0));const points=rows.map((row,index)=>{const x=rows.length<2?width/2:pad+index*(width-pad*2)/(rows.length-1);const y=height-pad-(Number(row.count)||0)/max*(height-pad*2);return {x,y,row};});const poly=points.map(p=>`${p.x},${p.y}`).join(' ');return `<article class="analytics-card timeline-card"><h3>Actividad de escaneos · cronología</h3>${points.length?`<svg class="timeline-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Escaneos por fecha"><line x1="${pad}" y1="${height-pad}" x2="${width-pad}" y2="${height-pad}"/><line x1="${pad}" y1="${pad}" x2="${pad}" y2="${height-pad}"/><polyline points="${poly}"/>${points.map(p=>`<circle cx="${p.x}" cy="${p.y}" r="4"><title>${esc(p.row.day)}: ${Number(p.row.count)||0} escaneos</title></circle>`).join('')}${points.map(p=>`<text x="${p.x}" y="${height-6}" text-anchor="middle">${esc(p.row.day.slice(5))}</text>`).join('')}</svg>`:'<p class="muted">Sin escaneos registrados.</p>'}</article>`; }
async function loadAnalytics() {
  try {
    const d = await api('/api/analytics');
    $('analytics-grid').innerHTML = severityDonut(d.severities) + chart('Hallazgos por motor', d.sources, 'source') + fileRanking(d.files) + categoryTiles(d.categories) + timelineSvg(d.timeline);
    $('analytics-grid').querySelectorAll('[data-history-category]').forEach((button) => button.addEventListener('click', () => showHistory({ category: button.dataset.historyCategory })));
    $('analytics-grid').querySelectorAll('[data-history-file]').forEach((button) => button.addEventListener('click', () => showHistory({ file: button.dataset.historyFile })));
  } catch (error) { $('analytics-grid').innerHTML = `<div class="empty-state">${esc(error.message)}</div>`; }
}
async function loadKeys() {
  try {
    const data = await api('/api/state'); const cloud = data.cloud;
    window.auditCloudReady = cloud.enabled; window.auditCloudReason = cloud.reasons.join(' ');
    const keyStatus = cloud.keys.length ? `${cloud.keys.length} clave(s) guardada(s) localmente` : 'No hay claves guardadas';
    const requirements = [
      ['CLAVE API', cloud.keys.length ? 'ENCONTRADA' : 'FALTA', !!cloud.keys.length],
      ['ENDPOINT', cloud.urlConfigured ? cloud.endpointHost || 'CONFIGURADO' : 'FALTA URL', !!cloud.urlConfigured],
      ['CLIENTE', cloud.clientAvailable ? 'DISPONIBLE' : 'NO DISPONIBLE', !!cloud.clientAvailable],
      ['POLÍTICA PULSE', cloud.policyEnabled ? 'HABILITADA' : 'DESACTIVADA', !!cloud.policyEnabled],
    ];
    $('cloud-status-panel').innerHTML = `<div class="cloud-status-head"><div><p class="eyebrow">PULSE READINESS</p><strong>${cloud.enabled ? 'Listo para escanear' : 'Clave detectada; configuración pendiente'}</strong><small>${esc(keyStatus)}</small></div><span class="badge ${cloud.enabled ? '' : 'warn'}">${cloud.enabled ? 'ACTIVO' : 'INACTIVO'}</span></div><div class="cloud-requirements">${requirements.map(([label,value,ready])=>`<div class="cloud-requirement ${ready?'ready':''}"><small>${esc(label)}</small><strong>${esc(value)}</strong></div>`).join('')}</div>${cloud.reasons.length ? `<p class="cloud-reason">${esc(cloud.reasons.join(' '))}</p>` : '<p class="cloud-reason">El escaneo Pulse enviará el checkout fijado por SHA al endpoint seleccionado cuando inicies ese modo.</p>'}`;
    $('key-list').innerHTML = cloud.keys.length ? cloud.keys.map((key)=>`<div class="key-row"><div class="key-info"><strong>${esc(key.name)}</strong><code>${esc(key.maskedToken)}</code><small class="muted">Agregada ${esc(key.addedAt||'')}</small></div><button class="button danger" data-revoke="${esc(key.id)}">Eliminar localmente</button></div>`).join('') : '<div class="empty-state">No hay claves de Sentinel Cloud guardadas. Agrega una clave y configura el endpoint para activar Pulse.</div>';
    document.querySelectorAll('[data-revoke]').forEach((button)=>button.addEventListener('click',async()=>{if(!confirm('Eliminar esta clave del almacén local? Esto no revoca el token en Sentinel Cloud.'))return;try{const result=await api(`/api/keys/${encodeURIComponent(button.dataset.revoke)}`,{method:'DELETE'});toast(result.warning);loadKeys();loadState();refreshCloud();}catch(error){toast(error.message)}}));
  } catch(error) { $('key-list').innerHTML=`<div class="empty-state">${esc(error.message)}</div>`; }
}
async function configureCloudPulse({ pendingScan = null } = {}) {
  try {
    const current = await api('/api/cloud/settings');
    const keyCount = current.keys && current.keys.length ? current.keys.length : 0;
    const keySummary = keyCount ? `${keyCount} clave(s) local(es) detectada(s). Pulse usará la clave seleccionada al iniciar el escaneo.` : 'No hay claves locales de Sentinel Cloud. Guarda una en Claves API antes de iniciar Pulse.';
    const endpointHint = current.endpointSource === 'default' ? `Se usará el endpoint público por defecto: ${current.defaultUrl}.` : current.endpointSource === 'environment' ? 'La URL proviene de SENTINEL_CLOUD_URL.' : 'La URL proviene de la configuración local.';
    const form = `<form id="cloud-settings-form" class="form-grid"><label>URL del servicio Sentinel Cloud<input name="url" type="url" spellcheck="false" placeholder="${esc(current.defaultUrl || 'https://cloud.example.com')}" value="${esc(current.url || current.defaultUrl || '')}"></label><p class="muted">${esc(keySummary)} ${esc(endpointHint)} La URL se guarda en la configuración local del perfil; las claves existentes no se modifican.</p><label class="cloud-consent"><input name="enabled" type="checkbox" ${current.enabled || keyCount ? 'checked' : ''}><span><strong>Habilitar Sentinel Cloud · Pulse</strong><small>Autorizo que los escaneos Pulse envíen el checkout fijado por SHA al endpoint indicado. No se enviará código hasta que inicie un escaneo Pulse.</small></span></label><div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cancelar</button><button class="button primary">Guardar configuración</button></div></form>`;
    showModal('Configurar Pulse en esta máquina', form);
    $('cloud-settings-form').addEventListener('submit', async (event) => {
      event.preventDefault(); const values = new FormData(event.currentTarget);
      try {
        const saved = await api('/api/cloud/settings', { method: 'POST', body: JSON.stringify({ url: values.get('url'), enabled: values.get('enabled') === 'on' }) });
        $('modal-root').replaceChildren(); await loadKeys(); await loadState(); await refreshCloud();
        toast(saved.enabled ? 'Pulse quedó habilitado. El código solo se envía cuando inicias un escaneo Pulse.' : 'Configuración guardada; Pulse permanece desactivado.');
        if (saved.enabled && pendingScan && state.selectedRepo) await launchScan(state.selectedRepo, pendingScan, 'pulse');
      } catch (error) { toast(error.message); }
    });
  } catch (error) { toast(`No se pudo cargar la configuración de Pulse: ${error.message}`); }
}
$('configure-cloud-open').addEventListener('click', configureCloudPulse);
$('add-key-open').addEventListener('click',()=>showModal('Agregar clave Sentinel Cloud',`<form id="key-form" class="form-grid"><label>Nombre visible<input name="name" maxlength="60" placeholder="Producción, investigación…" required></label><label>Token API<input name="token" type="password" autocomplete="new-password" required minlength="6"></label><p class="muted">El token se guarda mediante el almacén local de Sentinel Audit. La aplicación web nunca lo vuelve a mostrar.</p><div class="form-actions"><button type="button" class="button subtle" data-close-modal>Cancelar</button><button class="button primary">Guardar clave</button></div></form>`));
$('modal-root').addEventListener('submit',async(event)=>{if(event.target.id!=='key-form')return;event.preventDefault();const form=new FormData(event.target);try{await api('/api/keys',{method:'POST',body:JSON.stringify({name:form.get('name'),token:form.get('token')})});$('modal-root').replaceChildren();toast('Clave guardada en el almacén local.');loadKeys();loadState();refreshCloud();}catch(error){toast(error.message)}});
$('db-table').addEventListener('change',loadDatabase);$('refresh-repos').addEventListener('click',()=>loadRepos({silent:true}));$('close-prs').addEventListener('click',closePulls);if($('back-button'))$('back-button').addEventListener('click',goBack);$('refresh-analytics').addEventListener('click',loadAnalytics);document.addEventListener('keydown',(event)=>{if(event.key==='Escape'){if($('modal-root').childElementCount){$('modal-root').replaceChildren();return;}goBack();}});
Promise.all([loadState(),loadRepos(),loadRecent(),refreshCloud()]);
