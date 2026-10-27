'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Writable } = require('node:stream');
const { createTerminalProgress, plain } = require('../workflow/terminal-progress');

function capture() {
  const stream = new Writable({ write(chunk, _encoding, callback) { this.output += chunk.toString(); callback(); } });
  stream.output = '';
  stream.isTTY = false;
  return stream;
}

test('progress map records specialist states and sanitizes terminal control sequences', () => {
  const stream = capture();
  const progress = createTerminalProgress({ stream, color: false });
  progress.update({ stage: 'ENGINE', state: 'RUNNING', detail: 'local engine' });
  progress.update({ stage: 'SPECIALISTS', state: 'RUNNING' });
  progress.update({ tool: 'semgrep', state: 'QUEUED', detail: 'light queue' });
  progress.update({ tool: 'semgrep', state: 'RUNNING', detail: 'scanning' });
  progress.update({ tool: 'semgrep', state: 'COMPLETE', detail: '24 ms' });
  progress.finish();
  assert.match(stream.output, /Motor Sentinel: RUNNING/);
  assert.match(stream.output, /semgrep: COMPLETE — 24 ms/);
  assert.doesNotMatch(stream.output, /\u001b\[/);
  assert.equal(plain('safe\u001b[31mred'), 'safe [31mred');
});
