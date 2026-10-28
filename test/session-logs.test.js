'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const logs = require('../lib/session-logs');

test('session capture strips terminal controls and redacts credentials', () => {
  logs.beginSession();
  const output = { text: '', write(value) { this.text += value; } };
  const restore = logs.captureStream(output);
  output.write('Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\n');
  output.write('api_token=sntl_abcdefghijklmnopqrstuvwxyz\n');
  restore(); logs.endSession();
  assert.match(output.text, /Bearer ghp_/);
  const rows = logs.getSessionLogs();
  assert.match(rows[0].text, /REDACTED_TOKEN/);
  assert.match(rows[1].text, /REDACTED/);
  assert.doesNotMatch(rows.map((row) => row.text).join('\n'), /ghp_abcdefghijklmnopqrstuvwxyz|sntl_abcdefghijklmnopqrstuvwxyz/);
});
