'use strict';

const ORDER = ['PREFLIGHT', 'IDENTITY', 'ENGINE', 'ROUTING', 'SPECIALISTS', 'CORRELATION', 'TRIAGE', 'CLEANUP'];
const LABELS = { PREFLIGHT: 'Preflight del repositorio', IDENTITY: 'Commit fijado y checkout aislado', ENGINE: 'Motor Sentinel', ROUTING: 'Enrutamiento de señales', SPECIALISTS: 'Analizadores especialistas', CORRELATION: 'Correlación de evidencias', TRIAGE: 'Triage de candidatos', CLEANUP: 'Limpieza del checkout' };
const ICONS = { PENDING: 'WAIT', RUNNING: 'RUN', COMPLETE: 'OK', FAILED: 'FAIL', TIMEOUT: 'TIMEOUT', CANCELLED: 'CANCEL', UNAVAILABLE: 'UNAVAILABLE', INCOMPLETE: 'PARTIAL', NOT_RUN: 'SKIP', PLANNED: 'PLAN', QUEUED: 'QUEUE' };

function plain(value) {
  return String(value == null ? '' : value).replace(/[\u0000-\u001f\u007f\u001b]/g, ' ').replace(/\s+/g, ' ').slice(0, 140);
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
    const out = ['Sentinel Audit | mapa de ejecución'];
    for (const name of ORDER) {
      const item = states[name];
      const detail = item.detail ? ' — ' + plain(item.detail) : '';
      const marker = item.state === 'RUNNING' ? 'RUN ' + ['|', '/', '-', '\\'][frame % 4] : ICONS[item.state] || '?';
      out.push('  [' + paint(item.state, marker) + '] ' + LABELS[name] + ': ' + item.state + detail);
      if (name === 'SPECIALISTS' && tools.size) {
        for (const [tool, status] of tools) {
          const toolMarker = status.state === 'RUNNING' ? 'RUN ' + ['|', '/', '-', '\\'][frame % 4] : ICONS[status.state] || '?';
          out.push('      [' + paint(status.state, toolMarker) + '] ' + plain(tool) + ': ' + status.state + (status.detail ? ' — ' + plain(status.detail) : ''));
        }
      }
    }
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
      if (stream.isTTY && running && !timer) timer = setInterval(() => { frame++; draw(); }, 100);
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
