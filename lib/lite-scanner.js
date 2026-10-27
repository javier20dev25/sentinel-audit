'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { DISCLAIMER_TEXT } = require('./cloud-keys');

const RULES = [
  {
    regex: /\beval\s*\(|\bnew\s+Function\s*\(|globalThis\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/,
    type: 'UNSAFE_EVAL', subcode: 'SAST-EVAL', category: 'malware', intent: 'MALICIOUS',
    severity: 'CRITICAL', confidence: 'high', riskScore: 90,
    title: 'Dynamic code execution (eval)', description: 'Obfuscated or dynamic code execution detected.'
  },
  {
    regex: /require\s*\(['"]child_process['"]\)|(?<!\.)\bspawn\b|(?<!\.)\bexec\b|(?<!\.)\bexecSync\b/,
    type: 'OS_CAPABILITY', subcode: 'SAST-PROCESS', category: 'malware', intent: 'SUSPICIOUS',
    severity: 'MEDIUM', confidence: 'high', riskScore: 50,
    title: 'OS process spawning', description: 'OS process spawning capability introduced.'
  },
  {
    regex: /\bfetch\s*\(|https?\.request|axios\.|got\.|curl|wget/,
    type: 'NETWORK_ACTIVITY', subcode: 'SAST-NETWORK', category: 'malware', intent: 'NEUTRAL',
    severity: 'LOW', confidence: 'medium', riskScore: 15,
    title: 'Network communication', description: 'Outbound network communication detected.'
  },
  {
    regex: /process\.env\.[A-Z_]{4,}|secrets\.|private_key/,
    type: 'ENV_ACCESS', subcode: 'SAST-ENV', category: 'malware', intent: 'SUSPICIOUS',
    severity: 'MEDIUM', confidence: 'high', riskScore: 50,
    title: 'Environment variable access', description: 'Access to system environment variables or secrets.'
  },
  {
    regex: /Buffer\.from\s*\(.*['"]base64['"]\)|\.toString\s*\(\s*['"]base64['"]\s*\)/,
    type: 'POTENTIAL_SECRET', subcode: 'SAST-BASE64', category: 'malware', intent: 'MALICIOUS',
    severity: 'HIGH', confidence: 'high', riskScore: 70,
    title: 'Base64 encoding/decoding', description: 'Base64 data transformation detected (potential exfiltration/obfuscation).'
  },
  {
    regex: /innerHTML\s*=|outerHTML\s*=/,
    type: 'DOM_INJECTION', subcode: 'SAST-DOM', category: 'vulnerability', intent: 'VULNERABILITY',
    severity: 'HIGH', confidence: 'high', riskScore: 70,
    title: 'DOM injection (XSS)', description: 'Unsafe DOM manipulation detected (XSS risk).'
  },
  {
    regex: /vm\.runInContext|vm\.runInNewContext/,
    type: 'SANDBOX_ESCAPE', subcode: 'SAST-VM', category: 'malware', intent: 'SUSPICIOUS',
    severity: 'HIGH', confidence: 'high', riskScore: 70,
    title: 'VM sandbox escape', description: 'Code execution in VM context detected.'
  },
  // --- Secret detection rules ---
  {
    regex: /(?:AWS|aws)_ACCESS_KEY_ID\s*[=:]\s*['"]?AKIA[0-9A-Z]{16}['"]?/,
    type: 'SECRET_AWS_KEY_ID', subcode: 'SEC-AWS-ID', category: 'secret', intent: 'EXFILTRATION',
    severity: 'CRITICAL', confidence: 'high', riskScore: 90,
    title: 'AWS Access Key ID', description: 'AWS Access Key ID exposed in plain text.'
  },
  {
    regex: /(?:AWS|aws)_SECRET_ACCESS_KEY\s*[=:]\s*['"]?[A-Za-z0-9\/+=]{40}['"]?/,
    type: 'SECRET_AWS_SECRET', subcode: 'SEC-AWS-SECRET', category: 'secret', intent: 'EXFILTRATION',
    severity: 'CRITICAL', confidence: 'high', riskScore: 95,
    title: 'AWS Secret Access Key', description: 'AWS Secret Access Key exposed in plain text.'
  },
  {
    regex: /gh[opsu]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22,}/,
    type: 'SECRET_GITHUB_TOKEN', subcode: 'SEC-GITHUB-TOKEN', category: 'secret', intent: 'EXFILTRATION',
    severity: 'CRITICAL', confidence: 'high', riskScore: 90,
    title: 'GitHub token', description: 'GitHub personal access token exposed.'
  },
  {
    regex: /sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}/,
    type: 'SECRET_STRIPE_KEY', subcode: 'SEC-STRIPE', category: 'secret', intent: 'EXFILTRATION',
    severity: 'CRITICAL', confidence: 'high', riskScore: 90,
    title: 'Stripe API key', description: 'Stripe live API key exposed.'
  },
  {
    regex: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----/,
    type: 'SECRET_SSH_KEY', subcode: 'SEC-SSH-KEY', category: 'secret', intent: 'EXFILTRATION',
    severity: 'CRITICAL', confidence: 'high', riskScore: 95,
    title: 'Private SSH key', description: 'Private cryptographic key exposed in plain text.'
  },
  // --- Lifecycle script analysis ---
  {
    regex: /"(?:preinstall|postinstall|prepare|prebuild|prestart)"\s*:\s*"[^"]*\b(?:curl|wget)\b[^"]*"/,
    type: 'LIFECYCLE_CURL_BASH', subcode: 'LIF-CURL-BASH', category: 'malware', intent: 'MALICIOUS',
    severity: 'CRITICAL', confidence: 'high', riskScore: 90,
    title: 'Lifecycle download+exec', description: 'Lifecycle script with curl/wget download — supply chain attack vector.'
  },
  {
    regex: /"(?:preinstall|postinstall|prepare|prebuild|prestart)"\s*:\s*"[^"]*(?:\bbash\b|\bsh\b|powershell|\.ps1|\bpython\b|\bnode\b|\beval\b)[^"]*"/,
    type: 'LIFECYCLE_SHELL_EXEC', subcode: 'LIF-SHELL', category: 'malware', intent: 'MALICIOUS',
    severity: 'CRITICAL', confidence: 'high', riskScore: 85,
    title: 'Lifecycle shell exec', description: 'Lifecycle script invoking shell or interpreter — supply chain execution vector.'
  },
  // --- Workflow risks ---
  {
    regex: /\bpull_request_target\b/,
    type: 'WORKFLOW_RISK', subcode: 'WF-001', category: 'workflow', intent: 'VULNERABILITY',
    severity: 'HIGH', confidence: 'high', riskScore: 70,
    title: 'pull_request_target trigger', description: 'Executes with elevated permissions in context of target repository.'
  },
  {
    regex: /permissions:\s*write-all/,
    type: 'WORKFLOW_RISK', subcode: 'WF-002', category: 'workflow', intent: 'MALICIOUS',
    severity: 'CRITICAL', confidence: 'high', riskScore: 85,
    title: 'write-all permissions', description: 'Grants full write access across all scopes in workflow.'
  },
  {
    regex: /(?:curl|wget)\s+\S[^|]*\|\s*(?:bash|sh|powershell|pwsh)/,
    type: 'WORKFLOW_RISK', subcode: 'WF-005', category: 'workflow', intent: 'MALICIOUS',
    severity: 'CRITICAL', confidence: 'high', riskScore: 85,
    title: 'Remote download piped to shell', description: 'curl|bash or wget|sh pattern detected.'
  }
];

function parseUnifiedDiff(raw) {
  if (!raw || typeof raw !== 'string') return [];
  const parts = raw.split(/(?=^diff --git )/m);
  const files = [];

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const m = trimmed.match(/^diff --git a\/\S+ b\/(.+)$/m);
    if (m) {
      files.push({ filename: m[1].trim(), patch: trimmed });
    }
  }

  if (files.length === 0 && raw.trim()) {
    const m = raw.match(/^\+\+\+ b\/(.+)$/m);
    const filename = m ? m[1].trim() : 'PR.diff';
    files.push({ filename, patch: raw });
  }

  return files;
}

function scanPatch(filename, patch) {
  const findings = [];
  const lines = patch.split('\n');
  let currentLine = 0;

  // Filename inspection
  const baseName = filename.split(/[/\\]/).pop() || filename;
  const lowerName = baseName.toLowerCase();
  if (lowerName === '.env' || lowerName.startsWith('.env.') || lowerName === '.env.example') {
    findings.push({
      type: 'SECRET_ENV_FILE', subcode: 'SEC-ENV-FILE', category: 'secret', intent: 'EXFILTRATION',
      file: filename, line: 0, severity: 'HIGH', confidence: 'high', riskScore: 75,
      title: 'Environment file added/modified', description: '.env configuration file may contain secrets.',
      snippet: `File: ${baseName}`
    });
  }

  lines.forEach(line => {
    if (line.startsWith('@@')) {
      const match = line.match(/\+(\d+)/);
      if (match) currentLine = parseInt(match[1], 10) - 1;
      return;
    }

    if (line.startsWith('+') && !line.startsWith('+++')) {
      currentLine++;
      const code = line.substring(1).trim();
      if (!code) return;

      for (const rule of RULES) {
        if (rule.regex.test(code)) {
          findings.push({
            type: rule.type,
            subcode: rule.subcode,
            category: rule.category,
            intent: rule.intent,
            file: filename,
            line: currentLine,
            severity: rule.severity,
            confidence: rule.confidence,
            riskScore: rule.riskScore,
            title: rule.title,
            description: rule.description,
            snippet: code.substring(0, 160)
          });
        }
      }
    } else if (!line.startsWith('-')) {
      currentLine++;
    }
  });

  return findings;
}

function auditPRDiff(rawDiff, meta = {}) {
  const files = parseUnifiedDiff(rawDiff);
  const allFindings = [];

  for (const f of files) {
    const fFindings = scanPatch(f.filename, f.patch);
    allFindings.push(...fFindings);
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of allFindings) {
    const s = String(f.severity).toLowerCase();
    if (counts[s] !== undefined) counts[s]++;
  }

  let verdict = 'PASS';
  let riskScore = 0;
  if (counts.critical > 0) {
    verdict = 'BLOCK';
    riskScore = Math.min(100, 70 + counts.critical * 10 + counts.high * 5);
  } else if (counts.high > 0) {
    verdict = 'BLOCK';
    riskScore = Math.min(85, 50 + counts.high * 10 + counts.medium * 3);
  } else if (counts.medium > 0) {
    verdict = 'REVIEW';
    riskScore = Math.min(50, 25 + counts.medium * 5);
  } else if (counts.low > 0) {
    verdict = 'PASS';
    riskScore = Math.min(20, counts.low * 2);
  }

  const contentHash = crypto.createHash('sha256').update(rawDiff, 'utf8').digest('hex');

  return {
    scanId: `lite_${Date.now()}_${contentHash.slice(0, 8)}`,
    engine: 'Sentinel Lite (Deterministic SAST)',
    mode: 'offline_local',
    repo: meta.repo || 'unknown/repo',
    prNumber: meta.prNumber || 0,
    author: meta.author || 'unknown',
    timestamp: new Date().toISOString(),
    contentHash,
    filesAnalyzed: files.length,
    verdict,
    riskScore,
    counts,
    findings: allFindings,
    disclaimer: DISCLAIMER_TEXT
  };
}

function exportToMarkdown(scanResult, customDir) {
  const downloadDir = customDir || path.join(os.homedir(), 'Downloads');
  if (!fs.existsSync(downloadDir)) {
    fs.mkdirSync(downloadDir, { recursive: true });
  }

  const filename = `sentinel-audit-pr-${scanResult.prNumber || 'scan'}-${Date.now()}.md`;
  const fullPath = path.join(downloadDir, filename);

  const lines = [
    `# 🛡️ Sentinel Audit — Reporte de Escaneo de Pull Request`,
    ``,
    `> **Modo:** ${scanResult.engine} (${scanResult.mode})  `,
    `> **Repositorio:** \`${scanResult.repo}\`  `,
    `> **Pull Request:** \`#${scanResult.prNumber}\`  `,
    `> **Autor:** \`${scanResult.author}\`  `,
    `> **Fecha de Análisis:** \`${scanResult.timestamp}\`  `,
    `> **Hash SHA-256 del Diff:** \`${scanResult.contentHash}\`  `,
    ``,
    `---`,
    ``,
    `## 📊 Resumen Ejecutivo`,
    ``,
    `| Veredicto de Seguridad | Puntuación de Riesgo | Archivos Analizados | Total de Amenazas |`,
    `| :--- | :--- | :--- | :--- |`,
    `| **${scanResult.verdict === 'BLOCK' ? '🛑 BLOCK (Fusión Bloqueada)' : scanResult.verdict === 'REVIEW' ? '⚠️ REVIEW (Requiere Revisión)' : '✅ PASS (Aprobado)'}** | **${scanResult.riskScore}/100** | ${scanResult.filesAnalyzed} | ${scanResult.findings.length} |`,
    ``,
    `### Desglose por Severidad:`,
    `- **CRITICAL:** ${scanResult.counts.critical}`,
    `- **HIGH:** ${scanResult.counts.high}`,
    `- **MEDIUM:** ${scanResult.counts.medium}`,
    `- **LOW:** ${scanResult.counts.low}`,
    ``,
    `---`,
    ``,
    `## 🔍 Hallazgos Detallados (${scanResult.findings.length})`,
    ``
  ];

  if (scanResult.findings.length === 0) {
    lines.push(`✅ **Sin anomalías detectadas:** El motor estático no identificó patrones maliciosos, credenciales expuestas ni modificaciones sospechosas en el payload.`);
  } else {
    scanResult.findings.forEach((f, idx) => {
      const badge = f.severity === 'CRITICAL' ? '🛑 [CRITICAL]' : f.severity === 'HIGH' ? '⚠️ [HIGH]' : f.severity === 'MEDIUM' ? '⚡ [MEDIUM]' : 'ℹ️ [LOW]';
      lines.push(`### ${idx + 1}. ${badge} ${f.title}`);
      lines.push(`- **Tipo:** \`${f.type}\` (\`${f.subcode}\`)`);
      lines.push(`- **Categoría / Intención:** \`${f.category}\` / \`${f.intent}\``);
      lines.push(`- **Ubicación:** \`${f.file}\` (Línea ${f.line || 'N/A'})`);
      lines.push(`- **Descripción:** ${f.description}`);
      if (f.snippet) {
        lines.push(``);
        lines.push(`\`\`\`javascript`);
        lines.push(f.snippet);
        lines.push(`\`\`\``);
      }
      lines.push(``);
    });
  }

  lines.push(`---`);
  lines.push(``);
  lines.push(`## ⚖️ Aviso Legal y Responsabilidad`);
  lines.push(`> ${scanResult.disclaimer}`);
  lines.push(``);
  lines.push(`*Generado automáticamente por Sentinel Security Intelligence Ecosystem.*`);

  const mdContent = lines.join('\n');
  fs.writeFileSync(fullPath, mdContent, 'utf8');

  return {
    filename,
    fullPath,
    bytes: Buffer.byteLength(mdContent, 'utf8')
  };
}

module.exports = {
  RULES,
  parseUnifiedDiff,
  scanPatch,
  auditPRDiff,
  exportToMarkdown
};
