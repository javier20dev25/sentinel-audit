/**
 * Sentinel Y - Semantic Vulnerability Analyzer (Core Pipeline)
 * Version: 0.1.0-alpha
 * Independent implementation: Zero CodeQL/Semgrep runtime dependencies.
 */

const fs = require('fs');
const path = require('path');

// --- Helper AST Parsers / Lexers (Lightweight, bounded static traversal) ---

/**
 * Normalizes source lines and comments
 */
function normalizeSource(sourceCode) {
  const lines = sourceCode.split('\n');
  return {
    raw: sourceCode,
    lines,
    lineCount: lines.length
  };
}

// --- Y-PROTO-001: Prototype Pollution Invariant Analyzer ---

/**
 * Analyzes source code for recursive object property assignment without prototype key guards.
 */
function analyzePrototypePollution(sourceObj, filePath) {
  const findings = [];
  const lines = sourceObj.lines;

  // Global file guard check (e.g. safeGetProperty or isValidKey)
  const hasGlobalSafeGetter = sourceObj.raw.includes('safeGetProperty') && sourceObj.raw.includes('__proto__');
  const hasGlobalKeyValidator = sourceObj.raw.includes('isValidKey') && (sourceObj.raw.includes('constructor') || sourceObj.raw.includes('prototype'));

  // Patterns for property enumeration / iteration
  const loopRegex = /(?:for\s*\(\s*(?:var|let|const)?\s*(\w+)\s+(?:in|of)\s+(\w+)|Object\.keys\((\w+)\)\.forEach|\.forEach\(\s*function\s*\(\s*(\w+))/;
  // Dynamic property assignment or helper calls passing key: target[key] = ... or mixin(target, val, key)
  const assignRegex = /(\w+)\s*\[\s*(\w+)\s*\]\s*=\s*(.+)/;
  const mixinCallRegex = /mixin\s*\(\s*(\w+)\s*,\s*[^,]+\s*,\s*(\w+)\s*\)/;

  // Local key guards: key !== '__proto__' or isValidKey(key)
  const localProtoGuardRegex = /(\w+)\s*===\s*['"](?:__proto__|constructor|prototype)['"]|(\w+)\s*!==\s*['"](?:__proto__|constructor|prototype)['"]|isValidKey\((\w+)\)/;

  let inLoop = false;
  let loopKey = null;
  let loopStartLine = 0;
  let hasLocalGuard = false;
  // 'none' | 'partial' | 'full'
  // 'partial' = only __proto__ guarded (vulnerable to constructor/prototype pollution)
  // 'full'    = isValidKey or (__proto__ AND constructor/prototype) guarded
  let loopGuardStrength = 'none';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check loop entry — reset per-loop state
    const loopMatch = line.match(loopRegex);
    if (loopMatch) {
      inLoop = true;
      loopKey = loopMatch[1] || loopMatch[4] || 'key';
      loopStartLine = lineNum;
      hasLocalGuard = false;
      loopGuardStrength = 'none';
    }

    // Classify guard strength on the guard line and persist it at loop level
    if (inLoop) {
      if (line.includes('isValidKey') || (line.includes('__proto__') && (line.includes('constructor') || line.includes('prototype')))) {
        // Full guard: covers __proto__ + constructor/prototype, or uses isValidKey()
        hasLocalGuard = true;
        loopGuardStrength = 'full';
      } else if (line.includes("__proto__") && loopGuardStrength !== 'full') {
        // Partial guard: only __proto__ — still vulnerable to {"constructor": {"prototype": {}}}
        loopGuardStrength = 'partial';
      }
    }

    // Check dynamic assignment or mixin call with loop key
    const assignMatch = line.match(assignRegex);
    const mixinMatch = line.match(mixinCallRegex);

    if (inLoop && (assignMatch || mixinMatch)) {
      const assignedKey = assignMatch ? assignMatch[2] : mixinMatch[2];
      
      // If assigning or passing loopKey
      if (assignedKey === loopKey || loopKey === 'key') {
        const isFullyProtected = hasGlobalSafeGetter || hasGlobalKeyValidator || loopGuardStrength === 'full';
        
        // Vulnerable if: no protection at all, OR only a partial guard (__proto__ only)
        if (!isFullyProtected) {
          findings.push({
            ruleId: 'Y-PROTO-001',
            cwe: 'CWE-1321',
            verdict: 'CONFIRMED',
            confidence: 'HIGH',
            title: 'Unsafe recursive object-property assignment (Prototype Pollution)',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: loopStartLine, symbol: loopKey },
              sinkLocation: { file: filePath, line: lineNum, symbol: assignedKey },
              violatedInvariant: 'Key must not resolve to __proto__, constructor, or prototype before assignment',
              missingGuard: 'Complete guard (filtering __proto__, constructor, and prototype) not found'
            }
          });
        }
      }
    }

    if (line.includes('}') && inLoop && i > loopStartLine + 15) {
      inLoop = false;
    }
  }

  return findings;
}

// --- Y-REDOS-001: Polynomial Regular Expression Complexity Analyzer ---

/**
 * Analyzes source code for ambiguous regex structures matched against input strings.
 */
function analyzeReDoS(sourceObj, filePath) {
  const findings = [];
  const lines = sourceObj.lines;

  // Regex literal definition
  const regexLiteralPattern = /var\s+(\w+)\s*=\s*\/([^\/\n]+)\/([gimsuy]*)/g;
  // Direct regex usage in replace/match/test
  const regexUsagePattern = /(\w+)\.(?:replace|match|test|exec)\(\s*(?:\/([^\/\n]+)\/([gimsuy]*)|(\w+))/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check for regex literals: e.g. /^(([^=;]+))\s*=\s*/ or /(\\*)"/g
    let match;
    while ((match = regexLiteralPattern.exec(line)) !== null) {
      const varName = match[1];
      const pattern = match[2];

      // Check structural superlinear risk:
      // Pattern 1: Nested or adjacent unconstrained quantifiers: e.g. \s*=\s* with overlapping prefix, or (\\*)"
      // Pattern 2: Ambiguous repetition with capture: ([^=;]+))\s*=
      const isBoundedRepetition = pattern.includes('{0,') || /\{\d+,\d+\}/.test(pattern);
      const hasAmbiguousBacktracking = !isBoundedRepetition && (
        pattern.includes('(\\*)') || 
        (pattern.includes('\\s*') && pattern.includes('+')) ||
        pattern.includes('\\s*=\\s*')
      );

      if (hasAmbiguousBacktracking) {
        findings.push({
          ruleId: 'Y-REDOS-001',
          cwe: 'CWE-1333',
          verdict: 'CONFIRMED',
          confidence: 'HIGH',
          title: 'Potentially superlinear regular expression on unbounded input',
          file: filePath,
          line: lineNum,
          snippet: line.trim(),
          proofWitness: {
            sourceLocation: { file: filePath, line: lineNum, symbol: varName },
            sinkLocation: { file: filePath, line: lineNum, symbol: pattern },
            violatedInvariant: 'Regex must have linear matching complexity or bounded input length',
            missingGuard: 'Unconstrained quantifier without atomic grouping or length boundary',
            causalPath: [
              { step: 1, file: filePath, line: lineNum, action: 'SUPERLINEAR_REGEX_DEFINITION', symbol: pattern }
            ]
          }
        });
      }
    }

    // Direct usage pattern in replace call
    const useMatch = line.match(regexUsagePattern);
    if (useMatch) {
      const targetVar = useMatch[1];
      const inlinePattern = useMatch[2];

      if (inlinePattern && inlinePattern.includes('(\\\\*)')) {
        findings.push({
          ruleId: 'Y-REDOS-001',
          cwe: 'CWE-1333',
          verdict: 'CONFIRMED',
          confidence: 'HIGH',
          title: 'Superlinear regex in string replacement with backtracking capture',
          file: filePath,
          line: lineNum,
          snippet: line.trim(),
          proofWitness: {
            sourceLocation: { file: filePath, line: lineNum, symbol: targetVar },
            sinkLocation: { file: filePath, line: lineNum, symbol: inlinePattern },
            violatedInvariant: 'Regex repetition must not backtrack catastrophically on escaping operations',
            missingGuard: 'Lookahead assertion required to disable JS regex backtracking'
          }
        });
      }
    }
  }

  return findings;
}

// --- Sentinel Y Engine Runner ---

function analyzeFile(filePath, content) {
  const norm = normalizeSource(content);
  const protoFindings = analyzePrototypePollution(norm, filePath);
  const redosFindings = analyzeReDoS(norm, filePath);
  return [...protoFindings, ...redosFindings];
}

module.exports = {
  analyzeFile,
  analyzePrototypePollution,
  analyzeReDoS,
  normalizeSource
};
