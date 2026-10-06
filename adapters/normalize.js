'use strict';
/**
 * Shared signal normalization for every Cloud provider.
 *
 * The local provider feeds raw engine alerts through this function; the hosted
 * provider feeds the server's public signal projection. Both must yield the same
 * finding shape, otherwise "the same repository through two providers" would
 * produce two different reports and cross-provider parity would be a claim
 * rather than a property. Keeping the transform in one module is what makes the
 * parity test meaningful.
 */
const path = require('path');
const crypto = require('crypto');

function cloudSignalCategory(signal) {
  const raw = JSON.stringify(signal).toLowerCase();
  const type = String(signal.type || signal.ruleName || signal.ruleId || signal.rule_id || signal.detector || '').toLowerCase();
  if (/secret|credential|token/.test(type)) return 'secret';
  if (/dependency|lockfile|sca|typosquat|vulnerable_dep/.test(type)) return 'dependency';
  if (/lifecycle|install_hook|postinstall/.test(type)) return 'lifecycle';
  if (/network|http|fetch|socket|exfil/.test(type) || /"intent":"(network|exfiltration)"/.test(raw)) return 'network';
  if (/filesystem|file_write|fs_write|write_file|persistence/.test(type)) return 'filesystem';
  if (/process|command|shell|exec|dynamic_execution|unsafe_eval/.test(type) || /"intent":"execution"/.test(raw)) return 'process';
  if (/capability_chain/.test(type)) {
    if (/execution|exec|process|shell/.test(raw)) return 'process';
    if (/network|fetch|http|exfil/.test(raw)) return 'network';
    if (/filesystem|file_write|write/.test(raw)) return 'filesystem';
  }
  return 'observation';
}

function normalizeCloudSignals(root, rawSignals) {
  const list = Array.isArray(rawSignals) ? rawSignals : [];
  return list.map((input, index) => {
    const signal = input && typeof input === 'object' ? input : {};
    const candidateValue = signal._fullPath || signal.file || signal._file || signal.filename || signal.path || null;
    const candidate = typeof candidateValue === 'string' && candidateValue.trim() ? candidateValue : null;
    const file = candidate ? path.resolve(root, candidate) : null;
    const rel = file ? path.relative(root, file) : '';
    const insideRoot = !!file && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
    const category = cloudSignalCategory(signal);
    const evidence = signal.evidence;
    const detail = [signal.title, signal.description, signal.message, signal.snippet,
      Array.isArray(evidence) ? evidence.join(' → ') : evidence,
      typeof signal.value === 'string' ? signal.value : null]
      .filter((part) => typeof part === 'string' && part.trim()).join(' | ');
    const line = Number.isInteger(signal.line) ? signal.line
      : Number.isInteger(signal.lineNumber) ? signal.lineNumber : null;
    return {
      signalId: 'SIG-' + crypto.createHash('sha256').update(JSON.stringify([
        signal.type || signal.ruleName || signal.ruleId || signal.rule_id || signal.detector || 'cloud_signal', file || '',
        line, detail, index,
      ])).digest('hex').slice(0, 16),
      tool: 'sentinel',
      rule: signal.type || signal.ruleName || signal.ruleId || signal.rule_id || signal.detector || 'cloud_signal',
      kind: signal.type || signal.ruleId || signal.rule_id || signal.detector || 'observation',
      category,
      file: insideRoot ? file : null,
      line,
      detail,
      signalClass: category !== 'observation' && insideRoot && !!detail ? 'ACTIONABLE_SIGNAL' : 'OBSERVATION_ONLY',
      rawEngineSignal: signal,
    };
  });
}

module.exports = { normalizeCloudSignals, cloudSignalCategory };
