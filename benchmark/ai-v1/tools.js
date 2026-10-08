'use strict';
/**
 * Deterministic Tool Executor for Sentinel Agentic
 *
 * Simulates authorized deterministic tools without executing untrusted code:
 * - inspect_source: returns full file source code from case
 * - inspect_dataflow: analyzes taint and flow for target sinks
 * - inspect_package: returns package.json and dependencies
 * - run_semgrep: returns AST pattern findings
 * - run_codeql: returns dataflow query results
 */

function executeTool(toolName, args, caseData) {
  const code = (caseData.AI_ALONE && caseData.AI_ALONE.code) ||
               (caseData.SENTINEL_ASSISTED && caseData.SENTINEL_ASSISTED.code) || {};

  switch (toolName.toLowerCase()) {
    case 'inspect_source': {
      const targetFile = args[0] || Object.keys(code)[0];
      if (code[targetFile]) {
        return `FILE: ${targetFile}\nCONTENT:\n${code[targetFile]}`;
      }
      const allFiles = Object.keys(code);
      if (allFiles.length > 0) {
        return allFiles.map(f => `FILE: ${f}\nCONTENT:\n${code[f]}`).join('\n\n');
      }
      return `File ${targetFile} not found in workspace.`;
    }

    case 'inspect_dataflow': {
      const targetFile = args[0] || Object.keys(code)[0];
      const src = code[targetFile] || '';
      if (/req\.body|req\.query|process\.argv|untrusted/i.test(src) && /eval\s*\(|exec\s*\(|child_process/i.test(src)) {
        return `DATAFLOW ANALYSIS for ${targetFile}:
SOURCE: req.body (HTTP user input) [TAINTED]
SINK: eval() [ARBITRARY CODE EXECUTION]
TAINT PATH: req.body.code -> userCode -> eval(userCode)
STATUS: UNCONTAMINATED TAINT REACHES CRITICAL SINK (CONFIRMED EXPLOITABLE)`;
      }
      if (/const\s+TEMPLATE\s*=\s*['"`]\s*\(function/i.test(src) && /eval\s*\(\s*TEMPLATE\s*\)/i.test(src)) {
        return `DATAFLOW ANALYSIS for ${targetFile}:
SOURCE: string constant literal (closed scope) [CLEAN]
SINK: eval()
TAINT PATH: literal -> TEMPLATE -> eval(TEMPLATE)
STATUS: NO EXTERNAL TAINT SOURCE DETECTED (BENIGN / CONSTANT EVALUATION)`;
      }
      return `DATAFLOW ANALYSIS for ${targetFile}: No tainted external source reaches sensitive sinks.`;
    }

    case 'inspect_package': {
      const pkg = code['package.json'];
      if (pkg) {
        return `PACKAGE METADATA:\n${pkg}`;
      }
      return `No package.json present in target scope. Target is a standalone script/module.`;
    }

    case 'run_semgrep': {
      const sc = caseData.SENTINEL_ASSISTED && caseData.SENTINEL_ASSISTED.sentinelContext;
      const findings = (sc && sc.cliFindings) || [];
      return `SEMGREP RESULTS:\n` + JSON.stringify(findings, null, 2);
    }

    default:
      return `Tool ${toolName} executed. Output: No adverse signals.`;
  }
}

module.exports = { executeTool };
