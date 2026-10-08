'use strict';
/**
 * Sentinel AI Benchmark — Response Parser
 *
 * Parses structured AI output into judgment records.
 * Input: raw model text output
 * Output: { confirmed, falsePositive, unknown, overallVerdict, findings, toolCalls }
 *
 * Rules:
 *  - Never modifies ground truth.
 *  - Parser tolerates imperfect formatting (greedy matching).
 *  - Unknown/unparseable defaults to UNKNOWN, never fabricates CONFIRMED.
 */

function parseVerdict(text) {
  if (!text) return 'UNKNOWN';
  const t = text.toUpperCase().trim();
  if (t === 'CONFIRMED') return 'CONFIRMED';
  if (t === 'FALSE_POSITIVE' || t === 'FP' || t === 'FALSE POSITIVE') return 'FALSE_POSITIVE';
  if (t === 'BENIGN') return 'BENIGN';
  if (t === 'UNKNOWN') return 'UNKNOWN';
  return 'UNKNOWN';
}

function parseSeverity(text) {
  if (!text) return null;
  const t = text.toUpperCase().trim();
  if (['CRITICAL','HIGH','MEDIUM','LOW','INFO'].includes(t)) return t;
  return null;
}

/**
 * parseResponse(raw, mode)
 *
 * Returns:
 *  {
 *    confirmed: number,
 *    falsePositive: number,
 *    unknown: number,
 *    overallVerdict: 'CONFIRMED'|'BENIGN'|'UNKNOWN',
 *    findings: Array<{ title, file, line, verdict, severity, reason }>,
 *    toolCalls: number,
 *    toolCallTypes: string[],
 *    rawResponse: string,
 *  }
 */
function parseResponse(raw, mode) {
  if (!raw || typeof raw !== 'string') {
    return { confirmed: 0, falsePositive: 0, unknown: 0, overallVerdict: 'UNKNOWN',
             findings: [], toolCalls: 0, toolCallTypes: [], rawResponse: raw || '' };
  }

  const findings = [];
  let toolCalls = 0;
  const toolCallTypes = [];

  // Parse FINDING / SIGNAL / CANDIDATE blocks
  const findingRegex = /(?:FINDING|SIGNAL|CANDIDATE)\s*:\s*([^\n]+)\n([\s\S]*?)(?=(?:FINDING|SIGNAL|CANDIDATE|SUMMARY|TOOL_REQUEST)\s*:|$)/gi;
  let m;
  while ((m = findingRegex.exec(raw)) !== null) {
    const block = m[2];
    const title = m[1].trim();
    const fileM = block.match(/FILE\s*:\s*([^\n]+)/i);
    const lineM = block.match(/LINE\s*:\s*([^\n]+)/i);
    const verdictM = block.match(/VERDICT\s*:\s*([^\n]+)/i);
    const severityM = block.match(/SEVERITY\s*:\s*([^\n]+)/i);
    const reasonM = block.match(/REASON\s*:\s*([\s\S]+?)(?=\n[A-Z_]+\s*:|$)/i);
    findings.push({
      title,
      file: fileM ? fileM[1].trim() : null,
      line: lineM ? lineM[1].trim() : null,
      verdict: parseVerdict(verdictM ? verdictM[1].trim() : 'UNKNOWN'),
      severity: parseSeverity(severityM ? severityM[1].trim() : null),
      reason: reasonM ? reasonM[1].trim().slice(0, 500) : null,
    });
  }

  // Parse SUMMARY block
  const summaryM = raw.match(/SUMMARY\s*:\s*([\s\S]+?)(?=\n---|\n#|$)/i);
  let confirmedCount = 0, fpCount = 0, unknownCount = 0;
  let overallVerdict = 'UNKNOWN';
  if (summaryM) {
    const sb = summaryM[1];
    const cM = sb.match(/CONFIRMED\s*:\s*(\d+)/i);
    const fM = sb.match(/FALSE_POSITIVE\s*:\s*(\d+)/i);
    const uM = sb.match(/UNKNOWN\s*:\s*(\d+)/i);
    const ovM = sb.match(/OVERALL_VERDICT\s*:\s*([^\n]+)/i);
    if (cM) confirmedCount = parseInt(cM[1], 10);
    if (fM) fpCount = parseInt(fM[1], 10);
    if (uM) unknownCount = parseInt(uM[1], 10);
    if (ovM) overallVerdict = parseVerdict(ovM[1].trim());
  } else {
    // Derive from findings if no summary block
    confirmedCount = findings.filter(f => f.verdict === 'CONFIRMED').length;
    fpCount = findings.filter(f => f.verdict === 'FALSE_POSITIVE').length;
    unknownCount = findings.filter(f => f.verdict === 'UNKNOWN').length;
    if (confirmedCount > 0) overallVerdict = 'CONFIRMED';
    else if (fpCount > 0 && confirmedCount === 0 && unknownCount === 0) overallVerdict = 'BENIGN';
    else overallVerdict = 'UNKNOWN';
  }

  // Parse TOOL_REQUEST lines (Agentic mode)
  const toolReqMatches = raw.match(/TOOL_REQUEST\s*:\s*([^\n]+)/gi) || [];
  toolCalls = toolReqMatches.length;
  for (const t of toolReqMatches) {
    const tname = t.replace(/TOOL_REQUEST\s*:\s*/i, '').trim().split(/\s+/)[0];
    if (tname && !toolCallTypes.includes(tname)) toolCallTypes.push(tname);
  }

  // Also count TOOL_CALLS_TOTAL from summary if present
  const tcTotalM = raw.match(/TOOL_CALLS_TOTAL\s*:\s*(\d+)/i);
  if (tcTotalM) toolCalls = Math.max(toolCalls, parseInt(tcTotalM[1], 10));

  return {
    confirmed: confirmedCount,
    falsePositive: fpCount,
    unknown: unknownCount,
    overallVerdict,
    findings,
    toolCalls,
    toolCallTypes,
    rawResponse: raw,
  };
}

/**
 * scoreRun(parsed, groundTruth)
 *
 * Compares parsed AI response against frozen ground truth.
 * Returns: { tp, tn, fp, fn, unknown }
 *
 * groundTruth: 'MALICIOUS' | 'BENIGN'
 * overallVerdict: 'CONFIRMED' | 'BENIGN' | 'UNKNOWN'
 */
function scoreRun(parsed, groundTruth) {
  const isPositive = groundTruth === 'MALICIOUS';
  const aiSaysPositive = parsed.overallVerdict === 'CONFIRMED';
  const aiSaysBenign = parsed.overallVerdict === 'BENIGN';
  const aiUnknown = parsed.overallVerdict === 'UNKNOWN';

  if (aiUnknown) {
    return { tp: 0, tn: 0, fp: 0, fn: 0, unknown: 1 };
  }
  if (isPositive && aiSaysPositive) return { tp: 1, tn: 0, fp: 0, fn: 0, unknown: 0 };
  if (!isPositive && aiSaysBenign) return { tp: 0, tn: 1, fp: 0, fn: 0, unknown: 0 };
  if (!isPositive && aiSaysPositive) return { tp: 0, tn: 0, fp: 1, fn: 0, unknown: 0 };
  if (isPositive && aiSaysBenign) return { tp: 0, tn: 0, fp: 0, fn: 1, unknown: 0 };
  return { tp: 0, tn: 0, fp: 0, fn: 0, unknown: 1 };
}

module.exports = { parseResponse, scoreRun, parseVerdict };
