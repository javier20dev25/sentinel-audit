'use strict';

const ORDER = ['PREFLIGHT', 'IDENTITY', 'ENGINE', 'ROUTING', 'SPECIALISTS', 'CORRELATION', 'TRIAGE', 'CLEANUP'];
const LABELS = { PREFLIGHT: 'Preflight', IDENTITY: 'Commit fijado', ENGINE: 'Motor Sentinel', ROUTING: 'Enrutamiento', SPECIALISTS: 'Especialistas', CORRELATION: 'Correlación', TRIAGE: 'Triage', CLEANUP: 'Limpieza' };
const ICONS = { PENDING: 'WAIT', RUNNING: 'RUN', COMPLETE: 'OK', FAILED: 'FAIL', TIMEOUT: 'TIMEOUT', CANCELLED: 'CANCEL', UNAVAILABLE: 'UNAVAILABLE', INCOMPLETE: 'PARTIAL', NOT_RUN: 'SKIP', PLANNED: 'PLAN', QUEUED: 'QUEUE' };
const STATUS_MARKS = { PENDING: '..', RUNNING: '>', COMPLETE: 'OK', FAILED: 'X', TIMEOUT: '!', CANCELLED: 'X', UNAVAILABLE: '!', INCOMPLETE: '!', NOT_RUN: '--', PLANNED: '~', QUEUED: '>>' };

function plain(value) {
  return String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f\u001b]/g, ' ').replace(/\s+/g, ' ').slice(0, 140);
}
function visible(value) {
  return String(value).replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '').length;
}

function createTerminalProgress({ stream = process.stderr, color = process.env.NO_COLOR == null && stream.isTTY && process.env.TERM !== 'dumb' } = {}) {
  const states = Object.fromEntries(ORDER.map((name) => [name, { state: 'PENDING', detail: '' }]));
  const tools = new Map();
  let started = false;
  let closed = false;
  let drawnLines = 0;
  let frame = 0;
  let timer = null;
  const paint = (state, value) => {
    if (!color) return value;
    const code = state === 'COMPLETE' ? 32 : ['FAILED', 'TIMEOUT', 'CANCELLED', 'UNAVAILABLE'].includes(state) ? 31 : state === 'RUNNING' ? 36 : state === 'INCOMPLETE' ? 33 : 90;
    return '\u001b[' + code + 'm' + value + '\u001b[0m';
  };
  const lines = () => {
    const width = Math.min(92, Math.max(64, Number(stream.columns) || 76));
    const inner = width - 4;
    const top = `╭─ SENTINEL AUDIT  /  MAPA DE ANALISIS ${'─'.repeat(Math.max(0, width - 41))}╮`;
    const out = [paint('1;36', top)];
    const row = (text) => `│ ${text}${' '.repeat(Math.max(0, inner - visible(text)))} │`;
    for (const name of ORDER) {
      const item = states[name];
      const marker = item.state === 'RUNNING' ? ['|', '/', '-', '\\'][frame % 4] : STATUS_MARKS[item.state] || '?';
      const stateText = item.state === 'COMPLETE' ? 'LISTO' : item.state === 'PENDING' ? 'EN ESPERA' : item.state;
      const primary = `${paint(item.state, marker)}  ${LABELS[name].padEnd(22)} ${paint(item.state, stateText)}`;
      out.push(row(primary));
      if (item.detail) out.push(row(`   ${plain(item.detail).slice(0, inner - 5)}`));
      if (name === 'SPECIALISTS' && tools.size) {
        for (const [tool, status] of tools) {
          const toolMarker = status.state === 'RUNNING' ? ['|', '/', '-', '\\'][frame % 4] : STATUS_MARKS[status.state] || '?';
          const toolState = status.state === 'COMPLETE' ? 'LISTO' : status.state === 'PENDING' ? 'EN ESPERA' : status.state;
          out.push(row(`   ${paint(status.state, toolMarker)}  ${plain(tool).padEnd(20)} ${paint(status.state, toolState)}`));
          if (status.detail) out.push(row(`      ${plain(status.detail).slice(0, inner - 8)}`));
        }
      }
    }
    out.push(paint('1;36', `╰${'─'.repeat(width - 2)}╯`));
    return out;
  };
  const draw = () => {
    if (closed || !stream.isTTY) return;
    const rendered = lines();
    if (started) stream.write('\u001b[' + drawnLines + 'A\u001b[J');
    stream.write(rendered.join('\n') + '\n');
    started = true;
    drawnLines = rendered.length;
  };
  return {
    update(event) {
      if (!event || closed) return;
      const key = event.tool ? String(event.tool).toLowerCase() : event.stage;
      if (event.tool && !tools.has(key)) tools.set(key, { state: 'QUEUED', detail: '' });
      const item = event.tool ? tools.get(key) : states[key];
      if (!item) return;
      item.state = event.state || item.state;
      item.detail = plain(event.detail || '');
      const running = Object.values(states).some((stage) => stage.state === 'RUNNING') || [...tools.values()].some((tool) => tool.state === 'RUNNING');
      if (stream.isTTY && running && !timer) timer = setInterval(() => { frame++; draw(); }, 300);
      if ((!stream.isTTY || !running) && timer) { clearInterval(timer); timer = null; }
      if (stream.isTTY) draw();
      else stream.write('[' + (ICONS[item.state] || item.state) + '] ' + (event.tool ? plain(event.tool) : LABELS[event.stage] || plain(event.stage)) + ': ' + item.state + (item.detail ? ' — ' + item.detail : '') + '\n');
    },
    finish() {
      if (closed) return;
      closed = true;
      if (timer) clearInterval(timer);
      timer = null;
      if (stream.isTTY) {
        if (started) stream.write('\n');
      } else stream.write('\n' + lines().join('\n') + '\n');
    },
  };
}

module.exports = { createTerminalProgress, plain };
