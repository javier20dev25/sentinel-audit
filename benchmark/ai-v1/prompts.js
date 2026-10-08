'use strict';
/**
 * Sentinel AI Benchmark — Prompt Builder
 *
 * Builds the exact prompts for each mode. The system prompt is versioned
 * (sha256 hash recorded in run). Ground truth is never in any prompt.
 *
 * Model: Anthropic Claude / Google Gemini (same model, same temp, all modes)
 * Temperature: 0 (or lowest supported for determinism)
 */

const crypto = require('crypto');

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// -------------------------------------------------------------------------
// SYSTEM PROMPTS (versioned)
// -------------------------------------------------------------------------
const SYSTEM_PROMPTS = {
  AI_ALONE: `You are a senior application security engineer performing a code security review.
You will be given code or a diff. Your task is to identify security-relevant findings.

Rules:
- You CANNOT execute any code.
- You CANNOT install dependencies.
- You CANNOT access the internet.
- You CANNOT see Sentinel/scanner results.
- You CANNOT run tools (CodeQL, semgrep, etc.).
- You MUST reason only from the code provided.

For each finding, output:
  FINDING: <short title>
  FILE: <filename>
  LINE: <line number or range>
  VERDICT: CONFIRMED | FALSE_POSITIVE | UNKNOWN
  SEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFO
  REASON: <one paragraph explanation>

At the end, output a summary block:
  SUMMARY:
  CONFIRMED: <n>
  FALSE_POSITIVE: <n>
  UNKNOWN: <n>
  OVERALL_VERDICT: CONFIRMED | BENIGN | UNKNOWN`,

  SENTINEL_ASSISTED: `You are a senior application security engineer triaging Sentinel findings.
You will be given Sentinel Cloud + CLI normalized signals and the relevant code.

Rules:
- You CANNOT run new scanners.
- You CANNOT execute code.
- You MUST resolve each signal using only the evidence provided.
- You CANNOT access external resources.

For each candidate signal, output:
  SIGNAL: <type>
  FILE: <filename>
  LINE: <line number>
  VERDICT: CONFIRMED | FALSE_POSITIVE | UNKNOWN
  SEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFO
  REASON: <one paragraph based on the evidence provided>

At the end:
  SUMMARY:
  CONFIRMED: <n>
  FALSE_POSITIVE: <n>
  UNKNOWN: <n>
  OVERALL_VERDICT: CONFIRMED | BENIGN | UNKNOWN`,

  SENTINEL_AGENTIC: `You are a senior application security engineer working with the Sentinel Audit system.
You will be given a Sentinel Audit expediente and may request additional deterministic tool output.

Rules:
- You start with the Sentinel expediente.
- You MAY request tool outputs using: TOOL_REQUEST: <tool_name> <arguments>
- Available tools: inspect_source, inspect_dataflow, run_semgrep, run_codeql, inspect_package,
  inspect_dependencies, search_history, compare_commits.
- run_tests_if_safe is DISABLED for this target (untrusted code).
- You CANNOT execute code from the target repository.
- You decide WHEN to request more evidence. Don't request tools you don't need.
- After receiving tool output, continue reasoning.

For each candidate, output:
  CANDIDATE: <id>
  VERDICT: CONFIRMED | FALSE_POSITIVE | UNKNOWN
  SEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFO
  TOOL_CALLS: <n>
  REASON: <evidence-based explanation>

At the end:
  SUMMARY:
  CONFIRMED: <n>
  FALSE_POSITIVE: <n>
  UNKNOWN: <n>
  OVERALL_VERDICT: CONFIRMED | BENIGN | UNKNOWN
  TOOL_CALLS_TOTAL: <n>`,
};

const SYSTEM_PROMPT_HASHES = {
  AI_ALONE: sha256(SYSTEM_PROMPTS.AI_ALONE),
  SENTINEL_ASSISTED: sha256(SYSTEM_PROMPTS.SENTINEL_ASSISTED),
  SENTINEL_AGENTIC: sha256(SYSTEM_PROMPTS.SENTINEL_AGENTIC),
};

// -------------------------------------------------------------------------
// Task prompt builder
// -------------------------------------------------------------------------
function buildTaskPrompt(caseData, mode) {
  const input = caseData[mode];
  if (!input) throw new Error(`No input for mode ${mode} on case ${caseData.caseId}`);

  let prompt = `# Task: ${input.task}\n\n`;
  prompt += `**Context:** ${input.context}\n\n`;

  if (input.diff) {
    prompt += `## PR Diff Summary\n\`\`\`\n${input.diff}\n\`\`\`\n\n`;
  }

  if (input.sentinelContext) {
    const sc = input.sentinelContext;
    prompt += `## Sentinel Findings\n`;
    prompt += `Source: ${sc.source || 'Sentinel'}\n`;
    if (sc.cloudMeta) {
      prompt += `Cloud: totalSignals=${sc.cloudMeta.totalSignals}, ` +
                `actionable=${sc.cloudMeta.actionableSignals}, ` +
                `routingDecision=${sc.cloudMeta.routingDecision}\n`;
      if (sc.cloudMeta.promotedFiles && sc.cloudMeta.promotedFiles.length) {
        prompt += `Promoted files: ${sc.cloudMeta.promotedFiles.join(', ')}\n`;
      }
    }
    if (sc.cliFindings && sc.cliFindings.length) {
      prompt += `\n### CLI Findings (${sc.cliFindings.length})\n`;
      for (const f of sc.cliFindings) {
        prompt += `- [${f.severity}] ${f.type} @ ${f.file}:${f.line || '?'} — ${f.snippet || f.title || ''}\n`;
      }
    }
    if (sc.cloudFindings && sc.cloudFindings.length) {
      prompt += `\n### Cloud Findings (${sc.cloudFindings.length})\n`;
      for (const f of sc.cloudFindings) {
        prompt += `- [${f.severity || '?'}] ${f.type} @ ${f.file || '?'}:${f.line || '?'} riskScore=${f.riskScore||'?'} — ${f.snippet || f.title || ''}\n`;
      }
    }
    if (input.availableTools) {
      prompt += `\n### Available Tools\n${input.availableTools.join(', ')}\n`;
    }
    prompt += '\n';
  }

  if (input.code && Object.keys(input.code).length) {
    prompt += `## Code\n`;
    for (const [fname, content] of Object.entries(input.code)) {
      if (!content) continue;
      const ext = fname.split('.').pop();
      prompt += `### ${fname}\n\`\`\`${ext}\n${content}\n\`\`\`\n\n`;
    }
  }

  prompt += `\nAnalyze the above and produce your findings according to the system prompt format.`;
  return prompt;
}

module.exports = { SYSTEM_PROMPTS, SYSTEM_PROMPT_HASHES, buildTaskPrompt, sha256 };
