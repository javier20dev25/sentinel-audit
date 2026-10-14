/**
 * Sentinel Y - Semantic Vulnerability Analyzer (Core Pipeline)
 * Version: 0.3.0 (Independent Semantic Edition)
 * Independent implementation: Zero CodeQL/Semgrep runtime dependencies.
 *
 * Corrections for CE-01..CE-05 with conservative uncertainty when evidence insufficient.
 */

const fs = require('fs');
const path = require('path');

function normalizeSource(sourceCode) {
  const lines = String(sourceCode).split('\n');
  return {
    raw: sourceCode,
    lines,
    lineCount: lines.length
  };
}

function analyzePrototypePollution(sourceObj, filePath) {
  const findings = [];
  const lines = sourceObj.lines;
  const rawContent = sourceObj.raw;

  const hasGlobalSafeGetter = rawContent.includes('safeGetProperty') && rawContent.includes('__proto__');
  const hasGlobalKeyValidator = (rawContent.includes('isValidKey') || rawContent.includes('isProtoPath')) &&
    (rawContent.includes('constructor') || rawContent.includes('prototype'));
  const hasHelperGuardDef = /(?:function\s+|const\s+|var\s+|let\s+)(isPrototypePollution|isSafeKey|isValidKey|hasKey)\s*[\(=]/.test(rawContent);

  const loopRegex = /(?:for\s*\(\s*(?:var|let|const)?\s*(\w+)\s+(?:in|of)\s+([^)]+)|Object\.keys\((\w+)\)\.forEach|\.forEach\(\s*function\s*\(\s*(\w+))/;
  const assignRegex = /(\w+(?:\.\w+)?)\s*\[\s*(\w+)\s*\]\s*=\s*(.+)/;
  const mixinCallRegex = /(?:mixin|deepExtend|extend|merge)\s*\(\s*(\w+)\s*,\s*[^,]+\s*,\s*(\w+)\s*\)/;

  const hasRecursiveCall = /(?:mixin|deepExtend|extend|merge|internalize)\s*\(/i.test(rawContent);

  let inLoop = false;
  let loopKey = null;
  let loopSource = null;
  let loopStartLine = 0;
  let loopGuardStrength = 'none';
  let loopEnclosingFn = null;

  const localProtoGuardRegex = /(\w+)\s*===\s*['"](?:__proto__|constructor|prototype)['"]|(\w+)\s*!==\s*['"](?:__proto__|constructor|prototype)['"]|isValidKey\((\w+)\)|isProtoPath\((\w+)[^\)]*\)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const loopMatch = line.match(loopRegex);
    if (loopMatch) {
      inLoop = true;
      loopKey = loopMatch[1] || loopMatch[3] || loopMatch[4] || null;
      loopSource = loopMatch[2] || loopMatch[3] || null;
      loopStartLine = lineNum;
      loopGuardStrength = 'none';
      loopEnclosingFn = null;
      for (let b = i; b >= 0 && b > i - 40; b--) {
        const fnMatch = lines[b].match(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/);
        if (fnMatch) { loopEnclosingFn = fnMatch[1]; break; }
      }
      const guardLine = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 5)).join('\n');
      const g = guardLine.match(localProtoGuardRegex);
      if (g) {
        const isFull = /isValidKey|isProtoPath/i.test(guardLine) || (guardLine.includes('__proto__') && guardLine.includes('constructor') && guardLine.includes('prototype'));
        loopGuardStrength = isFull ? 'full' : (guardLine.includes('__proto__') ? 'partial' : 'none');
      }
      // Fall through so an assignment written on the same line as the loop
      // header is still analysed.
    }
    if (inLoop) {
      const assignMatch = line.match(assignRegex);
      const mixinMatch = line.match(mixinCallRegex);
      if (assignMatch || mixinMatch) {
        const assignedKey = (assignMatch ? assignMatch[2] : mixinMatch[3]);
        const targetExpr = (assignMatch ? assignMatch[1] : mixinMatch[1]);
        const assignedVal = (assignMatch ? assignMatch[3] : '').replace(/[;}\s]+$/, '');
        if (hasGlobalSafeGetter || hasGlobalKeyValidator || hasHelperGuardDef) {
          loopGuardStrength = 'full';
        }
        const isNullAssign = /^\s*null\b/.test(assignedVal.trim());
        const isPrimitiveAssign = /^(true|false|null|undefined|\d+|"[^"]*"|'[^']*'|\{.*\}|\[.*\])\s*;?$/.test(assignedVal.trim());
        const assignsToPrototype = targetExpr.includes('.prototype');
        const assignsToObjectProto = targetExpr.includes('Object.prototype');
        if (assignsToObjectProto) {
          if (loopGuardStrength !== 'full') {
            findings.push({
              ruleId: 'Y-PROTO-001',
              cwe: 'CWE-1321',
              verdict: 'CONFIRMED',
              confidence: 'HIGH',
              title: 'Dynamic write to Object.prototype without effective guard',
              file: filePath,
              line: lineNum,
              snippet: line.trim(),
              proofWitness: {
                sourceLocation: { file: filePath, line: loopStartLine, symbol: loopKey },
                sinkLocation: { file: filePath, line: lineNum, symbol: assignedKey },
                violatedInvariant: 'Key must not resolve to __proto__/constructor/prototype; writing to Object.prototype is high risk',
                missingGuard: loopGuardStrength === 'partial' ? 'Partial guard only (__proto__)' : 'No effective guard',
                mutationMode: 'OBJECT_PROTO_MUTATION'
              }
            });
          }
          continue;
        }
        if (assignsToPrototype) {
          if (loopGuardStrength !== 'full') {
            findings.push({
              ruleId: 'Y-PROTO-001',
              cwe: 'CWE-1321',
              verdict: 'CANDIDATE',
              confidence: 'MEDIUM',
              title: 'Dynamic assignment to class prototype (uncertain trust of keys/recipients)',
              file: filePath,
              line: lineNum,
              snippet: line.trim(),
              proofWitness: {
                sourceLocation: { file: filePath, line: loopStartLine, symbol: loopKey },
                sinkLocation: { file: filePath, line: lineNum, symbol: assignedKey },
                violatedInvariant: 'Prototype keys must be restricted/trusted; cannot assume safety from value type alone',
                missingGuard: loopGuardStrength === 'partial' ? 'Partial guard' : 'No guard demonstrated',
                mutationMode: 'CLASS_PROTO_MUTATION'
              }
            });
          }
          continue;
        }
        if (isNullAssign || isPrimitiveAssign) {
          findings.push({
            ruleId: 'Y-PROTO-001',
            cwe: 'CWE-1321',
            verdict: 'CANDIDATE',
            confidence: 'LOW',
            title: 'Dynamic assignment with primitive/null value (path to shared prototype unresolved)',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: loopStartLine, symbol: loopKey },
              sinkLocation: { file: filePath, line: lineNum, symbol: assignedKey },
              violatedInvariant: 'Destination receiver/path to shared prototype not statically resolved',
              missingGuard: loopGuardStrength === 'partial' ? 'Partial guard' : 'Guarding effectiveness unknown',
              mutationMode: 'PLAIN_MAP_ASSIGNMENT_UNRESOLVED_PATH'
            }
          });
          continue;
        }
        const isShallowConfigCopy = !hasRecursiveCall && (
          targetExpr.startsWith('this.settings') ||
          targetExpr.startsWith('header') ||
          targetExpr.startsWith('opts') ||
          targetExpr.startsWith('options') ||
          targetExpr.toLowerCase().startsWith('merged') ||
          (assignedVal.includes('[') && assignedVal.includes(assignedKey) && !assignedVal.includes('('))
        );
        if (isShallowConfigCopy && loopGuardStrength !== 'full') {
          findings.push({
            ruleId: 'Y-PROTO-001',
            cwe: 'CWE-1321',
            verdict: 'CANDIDATE',
            confidence: 'MEDIUM',
            title: 'Dynamic property copy on internal dictionary (shallow; prototype path uncertain)',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: loopStartLine, symbol: loopKey },
              sinkLocation: { file: filePath, line: lineNum, symbol: assignedKey },
              violatedInvariant: 'Key assigned dynamically without demonstrated effective prototype filter',
              missingGuard: loopGuardStrength === 'partial' ? 'Partial guard only' : 'No demonstrated guard',
              mutationMode: 'SHALLOW_ASSIGNMENT'
            }
          });
          continue;
        }
        if (loopGuardStrength !== 'full') {
          // A demonstrated recursive deep-merge sink (e.g. target[key] =
          // deepExtend(src, val) or mixin(...)) is a proven dangerous
          // mechanism, so it is confirmed. An unresolved dynamic write whose
          // path to a shared prototype is not established stays a candidate.
          const selfRecursiveWrite = (() => {
            if (!loopEnclosingFn || !/^[A-Za-z_$][\w$]*$/.test(assignedVal.trim())) return false;
            const body = lines.slice(Math.max(0, loopStartLine - 1), i + 1).join('\n');
            const re = new RegExp('(?:const|let|var)?\\s*' + assignedVal.trim() + '\\s*=\\s*' + loopEnclosingFn + '\\s*\\(');
            return re.test(body);
          })();
          const isRecursiveDeepMerge = !!mixinMatch || selfRecursiveWrite || /(?:mixin|deepExtend|extend|merge|internalize)\s*\(/i.test(assignedVal);
          findings.push({
            ruleId: 'Y-PROTO-001',
            cwe: 'CWE-1321',
            verdict: isRecursiveDeepMerge ? 'CONFIRMED' : 'CANDIDATE',
            confidence: isRecursiveDeepMerge ? 'HIGH' : 'MEDIUM',
            title: isRecursiveDeepMerge
              ? 'Unsafe recursive object-property assignment (Prototype Pollution)'
              : 'Unsafe dynamic property assignment (path to shared prototype unresolved)',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: loopStartLine, symbol: loopKey },
              sinkLocation: { file: filePath, line: lineNum, symbol: assignedKey },
              violatedInvariant: 'Effective guard against __proto__/constructor/prototype not demonstrated',
              missingGuard: loopGuardStrength === 'partial' ? 'Partial guard only (__proto__)' : 'No demonstrated guard',
              mutationMode: isRecursiveDeepMerge ? 'RECURSIVE_DEEP_MERGE' : 'DYNAMIC_PROPERTY_WRITE_UNRESOLVED'
            }
          });
          continue;
        }
      }
    }
    if (line.includes('}') && inLoop && i > loopStartLine + 40) {
      inLoop = false;
    }
  }
  return findings;
}

function parseRegexStructure(pattern) {
  const hasStar = pattern.includes('*');
  const hasPlus = pattern.includes('+');
  const hasBoundedRep = /\{\d+,\d*\}/.test(pattern);

  // A group that itself contains any quantifier (bounded or unbounded) and is
  // then repeated by an unbounded quantifier is ambiguous regardless of whether
  // the inner quantifier is bounded: the outer repetition still backtracks.
  const hasNestedQuantifier =
    /\([^)]*(?:[+*]|\{\d+,\d*\})[^)]*\)[+*]/.test(pattern) ||
    /\(\\{1,2}\*\)/.test(pattern);

  const hasOverlappingAlternation = /\((?:[0-9a-zA-Z_-]+\|[0-9a-zA-Z_-]+)\)[+*]/.test(pattern);
  const hasAdjacentOverlap = /([a-zA-Z0-9_-]+)\+\s*=\s*/.test(pattern) || /\\s\*=\\s\*/.test(pattern);
  const hasLookahead = pattern.includes('(?=') || pattern.includes('(?!');
  const hasAmbiguousStructure = hasNestedQuantifier || hasOverlappingAlternation || hasAdjacentOverlap;
  // Lookahead presence does not by itself neutralize an ambiguous structure; it
  // downgrades an otherwise-confirmed risk to an uncertain candidate.
  const isSuperlinearRisk = hasAmbiguousStructure && !hasLookahead;
  return {
    hasStar,
    hasPlus,
    hasBoundedRep,
    hasNestedQuantifier,
    hasOverlappingAlternation,
    hasAdjacentOverlap,
    hasLookaheadMitigation: hasLookahead,
    isSuperlinearRisk,
    hasAmbiguousStructure
  };
}

function analyzeReDoS(sourceObj, filePath) {
  const findings = [];
  const lines = sourceObj.lines;
  const regexLiteralPattern = /(?:var|let|const)\s+(\w+)\s*=\s*\/([^\/\n]+)\/([gimsuy]*)/g;
  const regexUsagePattern = /(\w+)\.(?:replace|match|test|exec)\(\s*(?:\/([^\/\n]+)\/([gimsuy]*)|(\w+))/g;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    let match;
    regexLiteralPattern.lastIndex = 0;
    while ((match = regexLiteralPattern.exec(line)) !== null) {
      const varName = match[1];
      const pattern = match[2];
      const struct = parseRegexStructure(pattern);
      if (struct.hasAmbiguousStructure) {
        if (struct.isSuperlinearRisk) {
          findings.push({
            ruleId: 'Y-REDOS-001',
            cwe: 'CWE-1333',
            verdict: 'CONFIRMED',
            confidence: 'HIGH',
            title: 'Ambiguous nested repetition without effective mitigation (ReDoS risk)',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: lineNum, symbol: varName },
              sinkLocation: { file: filePath, line: lineNum, symbol: pattern },
              violatedInvariant: 'Ambiguous repetition structure must be mitigated',
              missingGuard: 'No demonstrated effective mitigation',
              ambiguityType: struct.hasNestedQuantifier ? 'NESTED_QUANTIFIER' : (struct.hasOverlappingAlternation ? 'OVERLAPPING_ALTERNATION' : 'ADJACENT_OVERLAP'),
              mitigationEvaluated: { isLengthBounded: struct.hasBoundedRep, hasLookaheadGuard: struct.hasLookaheadMitigation }
            }
          });
        } else {
          findings.push({
            ruleId: 'Y-REDOS-001',
            cwe: 'CWE-1333',
            verdict: 'CANDIDATE',
            confidence: 'MEDIUM',
            title: 'Ambiguous repetition structure; mitigation efficacy uncertain',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: lineNum, symbol: varName },
              sinkLocation: { file: filePath, line: lineNum, symbol: pattern },
              violatedInvariant: 'Mitigation efficacy not demonstrated',
              missingGuard: struct.hasLookaheadMitigation ? 'Lookahead present but efficacy not demonstrated' : 'No mitigation demonstrated',
              ambiguityType: struct.hasNestedQuantifier ? 'NESTED_QUANTIFIER' : (struct.hasOverlappingAlternation ? 'OVERLAPPING_ALTERNATION' : 'ADJACENT_OVERLAP'),
              mitigationEvaluated: { isLengthBounded: struct.hasBoundedRep, hasLookaheadGuard: struct.hasLookaheadMitigation }
            }
          });
        }
      }
    }
    regexUsagePattern.lastIndex = 0;
    while ((match = regexUsagePattern.exec(line)) !== null) {
      const targetVar = match[1];
      const inlinePattern = match[2] || match[4];
      if (!inlinePattern) continue;
      const struct = parseRegexStructure(inlinePattern);
      if (struct.hasAmbiguousStructure) {
        if (struct.isSuperlinearRisk) {
          findings.push({
            ruleId: 'Y-REDOS-001',
            cwe: 'CWE-1333',
            verdict: 'CONFIRMED',
            confidence: 'HIGH',
            title: 'Superlinear regex in operation (ambiguous unmitigated)',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: lineNum, symbol: targetVar },
              sinkLocation: { file: filePath, line: lineNum, symbol: inlinePattern },
              violatedInvariant: 'Ambiguous repetition without demonstrated mitigation',
              missingGuard: 'Mitigation efficacy not assumed',
              ambiguityType: struct.hasNestedQuantifier ? 'NESTED_QUANTIFIER' : 'ADJACENT_OVERLAP',
              mitigationEvaluated: { isLengthBounded: struct.hasBoundedRep, hasLookaheadGuard: struct.hasLookaheadMitigation }
            }
          });
        } else {
          findings.push({
            ruleId: 'Y-REDOS-001',
            cwe: 'CWE-1333',
            verdict: 'CANDIDATE',
            confidence: 'MEDIUM',
            title: 'Ambiguous regex in operation; mitigation uncertain',
            file: filePath,
            line: lineNum,
            snippet: line.trim(),
            proofWitness: {
              sourceLocation: { file: filePath, line: lineNum, symbol: targetVar },
              sinkLocation: { file: filePath, line: lineNum, symbol: inlinePattern },
              violatedInvariant: 'Mitigation efficacy not demonstrated',
              missingGuard: struct.hasLookaheadMitigation ? 'Lookahead present but efficacy uncertain' : 'No mitigation demonstrated',
              ambiguityType: struct.hasNestedQuantifier ? 'NESTED_QUANTIFIER' : 'ADJACENT_OVERLAP',
              mitigationEvaluated: { isLengthBounded: struct.hasBoundedRep, hasLookaheadGuard: struct.hasLookaheadMitigation }
            }
          });
        }
      }
    }
  }
  return findings;
}

function analyzeFile(filePath, content) {
  const norm = normalizeSource(content);
  const protoFindings = analyzePrototypePollution(norm, filePath);
  const redosFindings = analyzeReDoS(norm, filePath);
  return [...protoFindings, ...redosFindings];
}

module.exports = {
  version: '0.3.0',
  analyzeFile,
  analyzePrototypePollution,
  analyzeReDoS,
  normalizeSource
};
