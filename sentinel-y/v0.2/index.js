/**
 * Sentinel Y - Semantic Vulnerability Analyzer (Core Pipeline)
 * Version: 0.2.0 (Hardened Semantic Edition)
 * Independent implementation: Zero CodeQL/Semgrep runtime dependencies.
 *
 * Implements:
 * - PHASE_Y2_2_PROTO_SPEC.md (Object identity, Receiver semantics, Invariant 4-Tuple, Shallow vs Deep)
 * - PHASE_Y2_2_REDOS_SPEC.md (Regex AST structure, Ambiguity detection, Grammar families, Mitigations)
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

// --- Y-PROTO-001: Prototype Pollution Invariant & Object Semantics Analyzer (v0.2) ---

/**
 * Analyzes source code for prototype pollution vulnerabilities using the Mutation 4-Tuple:
 * Vuln(op) <=> AttackerKey & PollutableReceiver & DangerousMutation & !EffectiveGuard
 */
function analyzePrototypePollution(sourceObj, filePath) {
  const findings = [];
  const lines = sourceObj.lines;
  const rawContent = sourceObj.raw;

  // 1. File-level defensive mechanisms
  const hasGlobalSafeGetter = rawContent.includes('safeGetProperty') && rawContent.includes('__proto__');
  const hasGlobalKeyValidator = (rawContent.includes('isValidKey') || rawContent.includes('isProtoPath')) &&
    (rawContent.includes('constructor') || rawContent.includes('prototype'));

  // 2. Inter-procedural helper summary (check if file defines helper guard functions)
  const hasHelperGuardDef = /(?:function\s+|const\s+|var\s+|let\s+)(isPrototypePollution|isSafeKey|isValidKey|hasKey)\s*[\(=]/.test(rawContent);

  // Patterns for property enumeration / iteration
  const loopRegex = /(?:for\s*\(\s*(?:var|let|const)?\s*(\w+)\s+(?:in|of)\s+([^)]+)|Object\.keys\((\w+)\)\.forEach|\.forEach\(\s*function\s*\(\s*(\w+))/;
  // Dynamic property assignment or helper calls passing key: target[key] = ... or mixin(target, val, key)
  const assignRegex = /(\w+(?:\.\w+)?)\s*\[\s*(\w+)\s*\]\s*=\s*(.+)/;
  const mixinCallRegex = /(?:mixin|deepExtend|extend|merge)\s*\(\s*(\w+)\s*,\s*[^,]+\s*,\s*(\w+)\s*\)/;

  // Check if function contains recursive invocation of itself or deep merger
  const hasRecursiveCall = /(?:mixin|deepExtend|extend|merge|internalize)\s*\(/i.test(rawContent);

  let inLoop = false;
  let loopKey = null;
  let loopSource = null;
  let loopStartLine = 0;
  let loopGuardStrength = 'none'; // 'none' | 'partial' | 'full'
  let loopHasHelperCall = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // A. Check loop entry
    const loopMatch = line.match(loopRegex);
    if (loopMatch) {
      inLoop = true;
      loopKey = loopMatch[1] || loopMatch[4] || 'key';
      loopSource = loopMatch[2] || loopMatch[3] || 'obj';
      loopStartLine = lineNum;
      loopGuardStrength = 'none';
      loopHasHelperCall = false;
    }

    // B. Check guard conditions inside loop
    if (inLoop) {
      // Full guard: covers __proto__ AND constructor/prototype, or uses isValidKey()
      if (
        line.includes('isValidKey') ||
        line.includes('isProtoPath') ||
        (line.includes('__proto__') && (line.includes('constructor') || line.includes('prototype')))
      ) {
        loopGuardStrength = 'full';
      } else if (line.includes('__proto__') && loopGuardStrength !== 'full') {
        // Partial guard: only __proto__ (vulnerable to Mode 2 recursive pollution)
        loopGuardStrength = 'partial';
      }

      // Check helper guard invocations like isPrototypePollution(key) or hasKey(obj, key)
      if (hasHelperGuardDef && /(?:isPrototypePollution|isSafeKey|isValidKey|hasKey)\s*\(/.test(line)) {
        loopHasHelperCall = true;
      }
    }

    // C. Check dynamic assignment or mixin call with loop key
    const assignMatch = line.match(assignRegex);
    const mixinMatch = line.match(mixinCallRegex);

    if (inLoop && (assignMatch || mixinMatch)) {
      const targetExpr = assignMatch ? assignMatch[1] : mixinMatch[1];
      const assignedKey = assignMatch ? assignMatch[2] : mixinMatch[2];
      const assignedVal = assignMatch ? assignMatch[3] : '';

      // Skip if assignment is using Object.defineProperty (immune own-property definition)
      if (line.includes('Object.defineProperty')) {
        continue;
      }

      // If assigning or passing loopKey
      if (assignedKey === loopKey || loopKey === 'key') {
        // 1. Is receiver immune, defensive, or class method installation?
        const isTargetImmune = line.includes('Object.defineProperty') || rawContent.includes('Object.create(null)');
        const isClassMethodInit = targetExpr.endsWith('.prototype') && (assignedVal.includes('function') || assignedVal.includes('=>'));
        if (isTargetImmune || isClassMethodInit) {
          continue; // CLEAN_WITHIN_SCOPE
        }

        // 2. Is key numerical or array index?
        const isNumericIndex = assignedKey === 'i' || assignedKey === 'index' || /^\d+$/.test(assignedKey);
        if (isNumericIndex) {
          continue; // CLEAN_WITHIN_SCOPE
        }

        // 2b. Is assigned value a primitive boolean, number, or symbol?
        const trimmedVal = assignedVal.trim().replace(/;$/, '');
        const isPrimitiveVal = trimmedVal === 'true' || trimmedVal === 'false' || trimmedVal === 'null' || trimmedVal === 'undefined' || /^\d+$/.test(trimmedVal);
        if (isPrimitiveVal) {
          continue; // CLEAN_WITHIN_SCOPE - Primitive cannot inject properties
        }

        // 3. Evaluate Guard Coverage
        const isFullyProtected = hasGlobalSafeGetter || hasGlobalKeyValidator || loopGuardStrength === 'full' || loopHasHelperCall;

        if (isFullyProtected) {
          continue; // CLEAN_WITHIN_SCOPE
        }

        // 4. Distinguish Shallow Option Copy vs Dangerous Recursive / Attacker Mutation
        // Shallow option copy: target is local dictionary (header, opts, options, merged*, this.settings)
        // without recursion inside the loop or function.
        const isShallowConfigCopy = !hasRecursiveCall && (
          targetExpr.startsWith('this.settings') ||
          targetExpr.startsWith('header') ||
          targetExpr.startsWith('opts') ||
          targetExpr.startsWith('options') ||
          targetExpr.toLowerCase().startsWith('merged') ||
          (assignedVal.includes('[') && assignedVal.includes(assignedKey) && !assignedVal.includes('('))
        );

        // If shallow option copy without recursive path: emit CANDIDATE with lower confidence, NOT CONFIRMED
        if (isShallowConfigCopy) {
          findings.push({
            ruleId: 'Y-PROTO-001',
            cwe: 'CWE-1321',
            verdict: 'CANDIDATE',
            confidence: 'MEDIUM',
            title: 'Dynamic property copy on internal dictionary (Shallow option copy)',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: loopStartLine, symbol: loopKey },
              sinkLocation: { file: filePath, line: lineNum, symbol: assignedKey },
              violatedInvariant: 'Key assigned dynamically without explicit prototype filter',
              missingGuard: 'No __proto__ guard, but receiver appears to be internal shallow configuration',
              mutationMode: 'SHALLOW_ASSIGNMENT'
            }
          });
        } else {
          // Dangerous recursive assignment or uncontrolled object merge -> CONFIRMED
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
              missingGuard: loopGuardStrength === 'partial'
                ? 'Partial guard only: filtering __proto__ is insufficient against constructor.prototype recursion'
                : 'Complete guard (filtering __proto__, constructor, and prototype) not found',
              mutationMode: hasRecursiveCall ? 'RECURSIVE_DEEP_MERGE' : 'DYNAMIC_PROPERTY_WRITE'
            }
          });
        }
      }
    }

    if (line.includes('}') && inLoop && i > loopStartLine + 25) {
      inLoop = false;
    }
  }

  return findings;
}

// --- Y-REDOS-001: Bounded Regular Expression Complexity Analyzer (v0.2) ---

/**
 * Parses regex pattern string into basic structural AST properties
 */
function parseRegexStructure(pattern) {
  // Check quantifiers
  const hasStar = pattern.includes('*');
  const hasPlus = pattern.includes('+');
  const hasBoundedRep = /\{\d+,\d+\}/.test(pattern) || pattern.includes('{0,');

  // Check nested quantifiers: (R+)*, (R*)+, (R+)+, (.*)*, (\\*)+
  const hasNestedQuantifier =
    /\([^)]*[+*][^)]*\)[+*]/.test(pattern) ||
    pattern.includes('(\\*)') ||
    /\(\\{1,2}\*\)/.test(pattern) ||
    /\(\[?[^\])]*[+*]\]?\)[+*]/.test(pattern);

  // Check overlapping alternation: (a|ab)+ or overlapping character sets
  const hasOverlappingAlternation =
    /\((?:[0-9a-zA-Z_-]+\|[0-9a-zA-Z_-]+)\)[+*]/.test(pattern) ||
    /\([0-9;]*[a-zA-Z]\)[+*]/.test(pattern);

  // Check adjacent unbounded repetition with overlap: \s*=\s* or [a-z]+[a-z]*
  const hasAdjacentOverlap =
    (/\\s\*=\\s\*/.test(pattern) && (hasPlus || pattern.includes('([^=;]+)'))) ||
    /([a-zA-Z0-9_-]+)\+\s*=\s*/.test(pattern);

  // Check mitigations: atomic lookahead assertion e.g. (?=\*?) or length limits
  const hasLookaheadMitigation = pattern.includes('(?=') || pattern.includes('(?!');

  return {
    hasStar,
    hasPlus,
    hasBoundedRep,
    hasNestedQuantifier,
    hasOverlappingAlternation,
    hasAdjacentOverlap,
    hasLookaheadMitigation,
    isSuperlinearRisk: !hasBoundedRep && !hasLookaheadMitigation && (hasNestedQuantifier || hasOverlappingAlternation || hasAdjacentOverlap)
  };
}

/**
 * Analyzes source code for polynomial/exponential regular expression complexity (ReDoS).
 */
function analyzeReDoS(sourceObj, filePath) {
  const findings = [];
  const lines = sourceObj.lines;

  // Regex literal definitions: var/let/const NAME = /PATTERN/FLAGS
  const regexLiteralPattern = /(?:var|let|const)\s+(\w+)\s*=\s*\/([^\/\n]+)\/([gimsuy]*)/g;
  // Inline regex in method calls: obj.replace(/PATTERN/FLAGS, ...), match, test, exec
  const regexUsagePattern = /(\w+)\.(?:replace|match|test|exec)\(\s*(?:\/([^\/\n]+)\/([gimsuy]*)|(\w+))/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check regex literals
    let match;
    while ((match = regexLiteralPattern.exec(line)) !== null) {
      const varName = match[1];
      const pattern = match[2];
      const flags = match[3];

      const struct = parseRegexStructure(pattern);

      if (struct.isSuperlinearRisk) {
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
            ambiguityType: struct.hasNestedQuantifier
              ? 'NESTED_QUANTIFIER'
              : struct.hasOverlappingAlternation
              ? 'OVERLAPPING_ALTERNATION'
              : 'ADJACENT_OVERLAP',
            mitigationEvaluated: {
              isLengthBounded: struct.hasBoundedRep,
              hasLookaheadGuard: struct.hasLookaheadMitigation
            }
          }
        });
      }
    }

    // Check inline regex usage
    const useMatch = line.match(regexUsagePattern);
    if (useMatch) {
      const targetVar = useMatch[1];
      const inlinePattern = useMatch[2];

      if (inlinePattern) {
        const struct = parseRegexStructure(inlinePattern);
        if (struct.isSuperlinearRisk) {
          findings.push({
            ruleId: 'Y-REDOS-001',
            cwe: 'CWE-1333',
            verdict: 'CONFIRMED',
            confidence: 'HIGH',
            title: 'Superlinear regex in string operation with backtracking capture',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: lineNum, symbol: targetVar },
              sinkLocation: { file: filePath, line: lineNum, symbol: inlinePattern },
              violatedInvariant: 'Regex repetition must not backtrack catastrophically on input operations',
              missingGuard: 'Lookahead assertion or length constraint required to disable backtracking',
              ambiguityType: struct.hasNestedQuantifier ? 'NESTED_QUANTIFIER' : 'ADJACENT_OVERLAP',
              mitigationEvaluated: {
                isLengthBounded: struct.hasBoundedRep,
                hasLookaheadGuard: struct.hasLookaheadMitigation
              }
            }
          });
        }
      }
    }
  }

  return findings;
}

// --- Sentinel Y v0.2 Engine Runner ---

function analyzeFile(filePath, content) {
  const norm = normalizeSource(content);
  const protoFindings = analyzePrototypePollution(norm, filePath);
  const redosFindings = analyzeReDoS(norm, filePath);
  return [...protoFindings, ...redosFindings];
}

module.exports = {
  version: '0.2.0',
  analyzeFile,
  analyzePrototypePollution,
  analyzeReDoS,
  normalizeSource
};
