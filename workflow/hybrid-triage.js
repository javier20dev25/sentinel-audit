'use strict';
/**
 * Local candidate follow-up hints.
 *
 * The same-file regex probe is a lightweight review aid. It does not run an
 * interprocedural analyzer, use an AI model, confirm a vulnerability, or prove
 * that a candidate is benign. Candidate adjudication remains human-led.
 */

const fs = require('fs');
const path = require('path');



const TRIAGE_STATES = {
  OBSERVATION: 'OBSERVATION',
  CANDIDATE: 'CANDIDATE',
  EVIDENCE_READY: 'EVIDENCE_READY',
  AI_REVIEW: 'AI_REVIEW',
  CONFIRMED: 'CONFIRMED',
  FALSE_POSITIVE: 'FALSE_POSITIVE',
  KNOWN_ALREADY: 'KNOWN_ALREADY',
  OUT_OF_SCOPE: 'OUT_OF_SCOPE',
  INSUFFICIENT_EVIDENCE: 'INSUFFICIENT_EVIDENCE',
  UNKNOWN: 'UNKNOWN'
};

/**
 * Checks whether a candidate matches the narrow local heuristic probe patterns.
 */
function isAmbiguousCandidate(candidate) {
  if (!candidate) return false;
  const rule = String(candidate.rule || candidate.type || '').toLowerCase();
  const detail = String(candidate.message || candidate.detail || candidate.snippet || '').toLowerCase();

  // Dynamic execution sinks with potential taint flow
  if (/eval|function_call|dynamic_execution|unsafe_eval/.test(rule)) return true;
  if (/child_process|exec|spawn|command_injection/.test(rule) && /req\.|param|body|query|process\.argv/.test(detail)) return true;
  if (/taint|dataflow|deserialization/.test(rule)) return true;

  return false;
}

/**
 * Runs read-only source inspection inside the pinned workspace.
 */
function runDeterministicTool(toolName, args, workspaceRoot) {
  const root = path.resolve(workspaceRoot);
  switch (toolName.toLowerCase()) {
    case 'inspect_source': {
      const targetFile = args[0] ? path.resolve(root, args[0]) : null;
      if (targetFile && targetFile.startsWith(root) && fs.existsSync(targetFile)) {
        const content = fs.readFileSync(targetFile, 'utf8');
        return `FILE: ${path.relative(root, targetFile)}\nCONTENT:\n${content.slice(0, 10000)}`;
      }
      return `File not accessible or out of bounds: ${args[0]}`;
    }

    case 'inspect_dataflow': {
      const targetRel = args[0];
      const targetFile = targetRel ? path.resolve(root, targetRel) : null;
      if (!targetFile || !targetFile.startsWith(root) || !fs.existsSync(targetFile)) {
        return `Target file not found: ${targetRel}`;
      }
      const src = fs.readFileSync(targetFile, 'utf8');

      // Taint analysis logic for JavaScript/Node
      if (/req\.body|req\.query|req\.params|process\.argv|untrusted/i.test(src) && /eval\s*\(|exec\s*\(|child_process/i.test(src)) {
        return `DATAFLOW ANALYSIS for ${targetRel}:
SOURCE: User-controlled input (HTTP/CLI parameter) [TAINTED]
SINK: eval() / child_process.exec() [CRITICAL SINK]
STATUS: UNCONTAMINATED TAINT REACHES SINK (EXPLOITABLE)`;
      }

      if (/const\s+[A-Za-z0-9_]+\s*=\s*['"`][^'"`]+['"`]/i.test(src) && /eval\s*\([A-Za-z0-9_]+\)/i.test(src)) {
        return `DATAFLOW ANALYSIS for ${targetRel}:
SOURCE: Static closed string literal constant [CLEAN]
SINK: eval()
STATUS: NO EXTERNAL TAINT SOURCE DETECTED (CONSTANT EVALUATION / BENIGN)`;
      }

      return `DATAFLOW ANALYSIS for ${targetRel}: No tainted external source reaches sensitive sinks.`;
    }

    case 'inspect_package': {
      const pkgPath = path.join(root, 'package.json');
      if (fs.existsSync(pkgPath)) {
        return `PACKAGE METADATA:\n${fs.readFileSync(pkgPath, 'utf8')}`;
      }
      return `No package.json found in repository root.`;
    }

    default:
      return `Tool ${toolName} not supported in deterministic sandbox.`;
  }
}

/**
 * Records non-adjudicating follow-up hints for Audit candidates.
 */
async function triageCandidatesHybrid(expediente, workspaceRoot, options = {}) {
  const results = [];
  const candidates = expediente.candidates || [];
  const triageLog = path.join(expediente.artifactDir || workspaceRoot, 'triage-run.jsonl');

  for (const candidate of candidates) {
    const candidateId = candidate.candidateId || candidate.id || 'CAND-UNKNOWN';
    const entry = {
      candidateId,
      state: TRIAGE_STATES.INSUFFICIENT_EVIDENCE,
      rule: candidate.rule,
      file: candidate.file,
      severity: candidate.severity,
      escalated: false,
      toolCalls: 0,
      toolsUsed: [],
      verdict: TRIAGE_STATES.UNKNOWN,
      reason: '',
      timestamp: new Date().toISOString(),
      method: 'local heuristic probe; no autonomous adjudication',
    };

    // Severity is useful for ordering work, but it cannot establish that a
    // vulnerability is real. Keep even a high-severity candidate open for a
    // reviewer instead of converting its label into a confirmation.
    if (!isAmbiguousCandidate(candidate)) {
      entry.reason = 'No targeted heuristic probe ran. Severity and tool correlation are prioritization signals, not proof; human verification is required.';
      results.push(entry);
      fs.appendFileSync(triageLog, JSON.stringify(entry) + '\n');
      continue;
    }

    const probe = runDeterministicTool('inspect_dataflow', [candidate.file], workspaceRoot);
    entry.toolCalls = 1;
    entry.toolsUsed.push('inspect_dataflow');
    const outcome = probe.includes('UNCONTAMINATED TAINT REACHES SINK')
      ? 'POSSIBLE_SOURCE_AND_SINK_CO_OCCURRENCE'
      : probe.includes('NO EXTERNAL TAINT SOURCE DETECTED')
        ? 'NO_EXTERNAL_SOURCE_MATCH_IN_SIMPLE_PATTERN'
        : 'NO_CONCLUSION';
    entry.heuristicProbe = {
      name: 'same-file regex source/sink probe',
      outcome,
      summary: probe,
      verdict: 'UNKNOWN',
      limitation: 'This heuristic does not build an interprocedural dataflow graph and cannot confirm exploitability or prove a candidate benign.',
    };
    entry.reason = `Heuristic probe: ${outcome}. Preserve the candidate for human review; this result is not a confirmation or a false-positive dismissal.`;
    results.push(entry);
    fs.appendFileSync(triageLog, JSON.stringify(entry) + '\n');
  }

  return results;
}
module.exports = {
  TRIAGE_STATES,
  isAmbiguousCandidate,
  runDeterministicTool,
  triageCandidatesHybrid
};
