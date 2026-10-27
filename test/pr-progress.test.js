'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Writable } = require('node:stream');
const { createPRProgress } = require('../workflow/pr-progress');

class Capture extends Writable {
  constructor() { super(); this.isTTY = false; this.text = ''; }
  _write(chunk, _encoding, callback) { this.text += chunk.toString(); callback(); }
}

test('Cloud PR map writes honest aggregate stages as plain text in pipes', () => {
  const stream = new Capture();
  const progress = createPRProgress({ stream });
  progress.update({ stage: 'PR', state: 'COMPLETE', detail: 'head sha-123' });
  progress.update({ stage: 'AUTH', state: 'COMPLETE', detail: 'plan Team' });
  progress.update({ stage: 'ENGINE', state: 'COMPLETE', detail: 'motor 5.0' });
  progress.update({ stage: 'RESULT', state: 'COMPLETE', detail: 'FLAG' });
  progress.finish();

  assert.match(stream.text, /PR #|Pull request fijado por SHA/);
  assert.match(stream.text, /motor 5\.0/);
  assert.match(stream.text, /no publica el progreso interno/);
  assert.doesNotMatch(stream.text, /\u001b\[/);
});
