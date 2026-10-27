'use strict';

const ORDER = ['PR', 'AUTH', 'ENGINE', 'RESULT'];
const LABELS = {
  PR: 'Pull request fijado por SHA',
  AUTH: 'Acceso a Sentinel Cloud',
  ENGINE: 'Motor de análisis',
  RESULT: 'Veredicto y evidencia',
};
const MARKERS = { PENDING: 'WAIT', RUNNING: 'RUN', COMPLETE: 'OK', FAILED: 'FAIL', NOT_RUN: 'SKIP' };

function clean(value) {
  return String(value || '').replace(/[\u0000-\u001f\u007f\u001b]/g, ' ').replace(/\s+/g, ' ').slice(0, 120);
}

function createPRProgress({ stream = process.stderr, engineLabel = 'Sentinel Cloud', note = 'El endpoint Cloud devuelve resultado agregado y no publica el progreso interno de sus analizadores.' } = {}) {
  const states = Object.fromEntries(ORDER.map((stage) => [stage, { state: 'PENDING', detail: '' }]));
  const color = process.env.NO_COLOR == null && !!stream.isTTY && process.env.TERM !== 'dumb';
  let frame = 0;
  let timer = null;
  let drawn = false;
  let closed = false;

  function render(changed) {
    if (closed) return;
    const rows = [`Sentinel Audit | PR | ${clean(engineLabel)} | mapa de análisis`];
    for (const stage of ORDER) {
      const item = states[stage];
      const marker = item.state === 'RUNNING' ? `RUN ${['|', '/', '-', '\\'][frame % 4]}` : MARKERS[item.state];
      const code = item.state === 'COMPLETE' ? 32 : item.state === 'RUNNING' ? 36 : item.state === 'FAILED' ? 31 : 90;
      const painted = color ? `\u001b[${code}m${marker}\u001b[0m` : marker;
      rows.push(`  [${painted}] ${LABELS[stage]}: ${item.state}${item.detail ? ` — ${item.detail}` : ''}`);
    }
    rows.push(`  ${clean(note)}`);
    if (!stream.isTTY) {
      const index = changed ? ORDER.indexOf(changed) + 1 : -1;
      stream.write((index >= 1 ? rows[index] : rows.join('\n')) + '\n');
      return;
    }
    if (drawn) stream.write(`\u001b[${rows.length}A\u001b[J`);
    stream.write(rows.join('\n') + '\n');
    drawn = true;
  }

  return {
    update({ stage, state, detail }) {
      if (closed || !states[stage]) return;
      states[stage] = { state, detail: clean(detail) };
      if (state === 'RUNNING' && stream.isTTY && !timer) {
        timer = setInterval(() => { frame++; render(stage); }, 100);
      } else if (state !== 'RUNNING' && timer) {
        clearInterval(timer);
        timer = null;
      }
      render(stage);
    },
    finish() {
      if (closed) return;
      if (timer) clearInterval(timer);
      timer = null;
      if (stream.isTTY) {
        if (drawn) stream.write('\n');
      } else render();
      closed = true;
    },
  };
}

module.exports = { createPRProgress, clean };
