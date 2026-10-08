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
const fs = require('fs');
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

  // Hosted evidence array tags mapping
  if (Array.isArray(signal.evidence)) {
    const evTags = signal.evidence.map((t) => String(t).toUpperCase());
    if (evTags.some((t) => ['ARBITRARY_EXEC', 'EXECUTION', 'SYSTEM'].includes(t))) return 'process';
    if (evTags.some((t) => ['NETWORK', 'REMOTE_SOURCE'].includes(t) || t.includes('.'))) return 'network';
    if (evTags.some((t) => ['SECRET', 'EMBEDDED_SECRET_POTENTIAL_LEAK'].includes(t))) return 'secret';
  }

  // Snippet / line text heuristic
  if (typeof signal.line === 'string') {
    const l = signal.line;
    if (/eval\(|cp\.exec|child_process|execSync|spawn/.test(l)) return 'process';
    if (/https?:\/\/|curl|fetch\(|socket/.test(l)) return 'network';
    if (/apiKey|api_key|token|secret/i.test(l)) return 'secret';
    if (/postinstall|preinstall/.test(l)) return 'lifecycle';
  }

  return 'observation';
}

function buildSourceIndex(root) {
  const index = [];
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!['.git', 'node_modules', 'dist', 'build', 'vendor'].includes(ent.name)) walk(full);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (['.js', '.ts', '.json', '.yml', '.yaml', '.py', '.sh', '.txt'].includes(ext)) {
          try {
            const lines = fs.readFileSync(full, 'utf8').split('\n');
            index.push({ file: full, rel: path.relative(root, full).replace(/\\/g, '/'), lines });
          } catch (_) {}
        }
      }
    }
  }
  walk(root);
  return index;
}

function locateSignalInFiles(signal, index, root) {
  // If line is string snippet with sufficient length, search exact line
  const lineText = typeof signal.line === 'string' ? signal.line.trim() : null;
  if (lineText && lineText.length >= 8) {
    for (const item of index) {
      for (let l = 0; l < item.lines.length; l++) {
        if (item.lines[l].includes(lineText)) {
          return { file: item.file, line: l + 1 };
        }
      }
    }
  }

  // If evidence array contains domain or indicator
  if (Array.isArray(signal.evidence)) {
    for (const token of signal.evidence) {
      if (typeof token === 'string' && token.includes('.') && !token.startsWith('[')) {
        for (const item of index) {
          for (let l = 0; l < item.lines.length; l++) {
            if (item.lines[l].includes(token)) {
              return { file: item.file, line: l + 1 };
            }
          }
        }
      }
    }
  }

  return null;
}

function normalizeCloudSignals(root, rawSignals) {
  const list = Array.isArray(rawSignals) ? rawSignals : [];
  let sourceIndex = null;

  return list.map((input, index) => {
    const signal = input && typeof input === 'object' ? input : {};
    let candidateValue = signal._fullPath || signal.file || signal._file || signal.filename || signal.path || null;
    let resolvedLine = Number.isInteger(signal.line) ? signal.line : Number.isInteger(signal.lineNumber) ? signal.lineNumber : null;

    if (!candidateValue && (typeof signal.line === 'string' || Array.isArray(signal.evidence))) {
      if (!sourceIndex) sourceIndex = buildSourceIndex(root);
      const loc = locateSignalInFiles(signal, sourceIndex, root);
      if (loc) {
        candidateValue = loc.file;
        if (resolvedLine == null) resolvedLine = loc.line;
      }
    }

    const candidate = typeof candidateValue === 'string' && candidateValue.trim() ? candidateValue : null;
    const file = candidate ? path.resolve(root, candidate) : null;
    const rel = file ? path.relative(root, file) : '';
    const insideRoot = !!file && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
    const category = cloudSignalCategory(signal);
    const evidence = signal.evidence;
    const severity = typeof signal.severity === 'number' ? signal.severity : 1;

    const detail = [
      signal.title, signal.description, signal.message, signal.snippet,
      Array.isArray(evidence) ? evidence.join(' → ') : (typeof evidence === 'string' ? evidence : null),
      typeof signal.line === 'string' ? signal.line : null,
      typeof signal.value === 'string' ? signal.value : null
    ].filter((part) => typeof part === 'string' && part.trim()).join(' | ');

    // ACTIONABLE_SIGNAL when category is an attack surface, located inside repo, with high/critical severity or explicit detail
    const isActionable = category !== 'observation' && insideRoot && (severity >= 4 || !!detail);

    return {
      signalId: 'SIG-' + crypto.createHash('sha256').update(JSON.stringify([
        signal.type || signal.ruleName || signal.ruleId || signal.rule_id || signal.detector || 'cloud_signal', file || '',
        resolvedLine, detail, index,
      ])).digest('hex').slice(0, 16),
      tool: 'sentinel',
      rule: signal.type || signal.ruleName || signal.ruleId || signal.rule_id || signal.detector || (category !== 'observation' ? `cloud_${category}` : 'cloud_signal'),
      kind: signal.type || signal.ruleId || signal.rule_id || signal.detector || category,
      category,
      file: insideRoot ? file : null,
      line: resolvedLine,
      detail,
      signalClass: isActionable ? 'ACTIONABLE_SIGNAL' : 'OBSERVATION_ONLY',
      rawEngineSignal: signal,
    };
  });
}

module.exports = { normalizeCloudSignals, cloudSignalCategory };
