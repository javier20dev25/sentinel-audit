'use strict';
/** Markdown expediente. Says what failed, not just what was found. */
const fs = require('fs');
const path = require('path');

const yn = (b) => (b ? 'yes' : 'no');

function renderReport(e) {
  const L = [];
  const w = (s) => L.push(s);
  const cov = (t) => {
    const x = e.tools[t];
    if (!x) return ['-', '-', '-', '-'];
    const c = x.coverage || {};
    return [x.status, `${c.filesSeen ?? '?'}/${c.filesEligible ?? '?'}`, c.filesParsed ?? '?', c.parseErrors ?? '?'];
  };

  w(`# Audit Expediente — ${e.name}`);
  w('');
  w(`- **Repo:** \`${e.repo}\``);
  w(`- **Commit:** \`${(e.commit || '').slice(0, 12)}\`  **Tree:** \`${(e.tree || '').slice(0, 12)}\`  **shallow:** ${e.shallow}`);
  const cloudIdentity = e.preflight.toolHealth && e.preflight.toolHealth.sentinel;
  if (cloudIdentity && cloudIdentity.available) {
    w(`- **Sentinel engine:** \`${cloudIdentity.engineId}\` · **Production parity:** ${cloudIdentity.productionParity || 'UNKNOWN'} — ${cloudIdentity.resultLabel || 'local engine; deployed parity unverified'}`);
  }
  w(`- **Started:** ${e.startedAt}  **Wall clock:** ${((e.totalWallClockMs || 0) / 60000).toFixed(1)}m`);
  w(`- **Preflight:** **${e.preflight.verdict}**  · disclosure: **${e.preflight.disclosure.verdict}**  · estimated ${e.preflight.estimatedMinutes}m`);
  w(`- **Publication:** push/PR/issue/report/email all **FORBIDDEN**. Fixes and drafts stay local.`);
  w('');

  w('## 1. Audit verdict');
  w('');
  w(`**${e.auditVerdict.verdict}**  ·  analysis state: **${e.auditVerdict.analysisState}**`);
  w('');
  w(e.auditVerdict.statement);
  w('');
  w(`- Can this audit claim "clean"? **${yn(e.auditVerdict.canClaimClean)}**`);
  if (e.preflight.disclosure) {
    const dj = e.preflight.disclosure;
    w(`- Disclosure channel: **${dj.verdict}** — source of truth: \`${dj.sourceOfTruth}\``);
    if (dj.channels && dj.channels.length) for (const c of dj.channels) w(`  - **route to use:** \`${c}\``);
    if (dj.contacts && dj.contacts.length) w(`  - monitored inbox: ${dj.contacts.join(', ')}`);
    if (dj.secondaryContacts && dj.secondaryContacts.length) w(`  - fallback only, do not lead with: ${dj.secondaryContacts.join(', ')}`);
    if (dj.retiredChannels && dj.retiredChannels.length) w(`  - retired by policy, not usable: ${dj.retiredChannels.join(', ')}`);
  }
  if (e.preflight.license) w(`- License: ${e.preflight.license.present ? `\`${e.preflight.license.file}\` (${e.preflight.license.sourceOfTruth})` : `**absent** (${e.preflight.license.sourceOfTruth})`}`);
  if (e.preflight.trackedFileCount != null) w(`- Tracked files: ${e.preflight.trackedFileCount}`);
  if (e.preflight.requiredRamMB) w(`- RAM required: ${e.preflight.requiredRamMB}MB${e.preflight.largeRepo ? ' (large repo)' : ''}`);
  if (e.preflight.limits && e.preflight.limits.length) {
    w('- Preflight limits:');
    for (const l of e.preflight.limits) w(`  - ${l}`);
  }
  if (e.auditVerdict.degradedTools.length) {
    w('');
    w('| Tool | Status | Reason |');
    w('|---|---|---|');
    for (const d of e.auditVerdict.degradedTools) w(`| ${d.tool} | ${d.status} | ${(d.reason || '-').replace(/\|/g, '/').slice(0, 100)} |`);
  }
  w('');

  w('## 2. Coverage and cost (Gates B and C)');
  w('');
  w('| Tool | Status | Verdict | seen/eligible | parsed | parse errors | coverage state | signals | wall ms |');
  w('|---|---|---|---|---|---|---|---|---|');
  for (const t of Object.keys(e.tools)) {
    const [s, se, p, pe] = cov(t);
    const x = e.tools[t];
    w(`| ${t} | ${s} | ${x.verdict} | ${se} | ${p} | ${pe} | ${(x.coverage && x.coverage.engineCoverage) || 'measured/other'} | ${x.findingCount} | ${x.cost.wallClockMs} |`);
  }
  w('');
  if (e.shortlist) w(`Sentinel Cloud promotion: **${e.shortlist.count} files**, origin \`${e.shortlist.origin}\`.`);
  if (e.signalRouting) w(`Signal routing: **${e.signalRouting.decision}** — ${e.signalRouting.reason}; tools: ${e.signalRouting.tools.join(', ') || 'none'}.`);
  w('');

  w('## 3. Candidates (corroborated by at least one dataflow or pattern authority)');
  w('');
  if (!e.candidates.length) {
    w('None. Note what that does and does not mean: see §1 before reading this as clean.');
  } else {
    w('| ID | Review | Priority | Disposition | Confidence | State | Tools | Location |');
    w('|---|---|---|---|---|---|---|---|');
    // Show the stored repo-relative path in full. Truncating it to a few
    // segments or reducing it to a basename is what made sixteen
    // playground/ssr/server.js fixtures collapse onto one indistinguishable
    // "server.js" row, and it also swallowed the packages/ prefix that
    // separates vite's own source from its playgrounds.
    const root = e.repo || e.repository;
    const loc = (f) => {
      let s = String(f || '').replace(/\\/g, '/');
      const r = String(root || '').replace(/\\/g, '/');
      if (r && s.toLowerCase().startsWith(r.toLowerCase())) s = s.slice(r.length);
      return s.replace(/^\/+/, '') || '(unknown)';
    };
    for (const c2 of e.candidates) w(`| ${c2.candidateId} | ${c2.reviewState || (c2.state === 'MANUALLY_VERIFIED' ? 'REVIEWED' : 'UNREVIEWED')} | ${c2.investigationPriority || '-'} | ${c2.disposition || '-'} | ${c2.confidence} | ${c2.state} | ${c2.tools.join('+')} | \`${loc(c2.file)}:${c2.line || '?'}\` |`);
    w('');
    for (const c2 of e.candidates) {
      w(`### ${c2.candidateId} — \`${c2.file}:${c2.line || '?'}\``);
      w('');
      w(`- **repo** \`${c2.repo}\``);
      w(`- **commit** \`${c2.commit}\`  **tree** \`${c2.tree}\`${c2.license ? `  **license** \`${c2.license}\`` : ''}`);
      w('');
      for (const s of c2.signals) {
        w(`- **${s.tool}** (${s.authority}) \`${s.rule}\`${s.verdictFromTool ? ` → ${s.verdictFromTool}` : ''}`);
        if (s.file) w(`  - file \`${s.file}\`${s.line ? `:${s.line}` : ''}`);
        if (s.source || s.sink) w(`  - source \`${s.source || '?'}\` → sink \`${s.sink || '?'}\`${s.sourceFile ? ` (source at \`${s.sourceFile}:${s.sourceLine || '?'}\`)` : ''}`);
        if (s.controls && s.controls.length) w(`  - controls: ${s.controls.join(', ')}`);
        if (s.blockedBy && s.blockedBy.length) w(`  - blocked by: ${s.blockedBy.join(', ')}`);
        if (s.path && s.path.length) {
          w(`  - path (${s.path.length} steps):`);
          for (const st of s.path.slice(0, 8)) w(`    ${String(st.line || '?').padStart(5)} | ${path.basename(st.file || '')}${(st.message || '') ? '  ' + st.message : ''}`);
          if (s.path.length > 8) w(`    ...and ${s.path.length - 8} more steps`);
        }
        if (s.detail) w(`  - ${s.detail.slice(0, 180)}`);
        if (s.snippet) {
          w('');
          w('  ```');
          for (const ln of s.snippet.text.split('\n')) w('  ' + ln);
          w('  ```');
        }
        w('');
      }
      if (c2.state === 'MANUALLY_VERIFIED') {
        w(`> **HUMAN ADJUDICATION — ${c2.disposition}${c2.severity ? ' (' + c2.severity + ')' : ''}**`);
        w(`> state \`${c2.state}\` · fingerprint \`${c2.fingerprint}\` · reportable: **${yn(c2.reportable)}**${c2.investigationPriority ? ` · investigation priority **${c2.investigationPriority}**` : ''}`);
        if (c2.rationale) { w('>'); w(`> ${c2.rationale}`); }
        w('');
        w(`> Tool confidence was **${c2.confidence}** from ${(c2.corroboratingAuthorities || []).length} corroborating authority(ies). The human decision above is what counts.`);
      } else {
        w(`> confidence **${c2.confidence}** from ${(c2.corroboratingAuthorities || []).length} corroborating authority(ies). Exploitability is **${c2.status}** — a human decides.`);
      }
      w('');
    }
  }

  const obs = e.observations || [];
  w(`## 3b. Breadth observations (${obs.length}) — leads, not findings`);
  w('');
  if (!obs.length) w('None.');
  else {
    w('Signals seen only by Sentinel Cloud remain observations until an independent dataflow or pattern authority corroborates them.');
    w('');
    w('| ID | Tools | Actionable signals | Location |');
    w('|---|---|---:|---|');
    for (const o of obs.slice(0, 60)) w(`| ${o.observationId} | ${o.tools.join('+')} | ${o.actionableSignals || 0} | \`${path.basename(o.file || '')}${o.line ? ':' + o.line : ''}\` |`);
    if (obs.length > 60) w(`\n_...and ${obs.length - 60} more, in \`expediente.json\`.`);
  }
  w('');

  w('## 4. Signals outside shipped code');
  w('');
  if (!e.nonProductionSignals.length) w('None.');
  else {
    const byScope = {};
    for (const s of e.nonProductionSignals) (byScope[s.scope] = byScope[s.scope] || []).push(s);
    for (const [scope, list] of Object.entries(byScope)) {
      w(`- **${scope}**: ${list.length} signals — ${[...new Set(list.map((s) => s.tool))].join(', ')}`);
    }
    w('');
    w('These are recorded, not deleted. A finding in `examples/` is not a finding in the library.');
  }
  w('');

  w('## 5. Local changes and drafts');
  w('');
  w(`- Branch: \`${e.localChanges.branch || 'none'}\``);
  w(`- Commit: \`${e.localChanges.commit || 'none'}\``);
  w(`- Patch: ${e.localChanges.patch || 'none'}`);
  w(`- Drafts: ${e.drafts.length ? e.drafts.join(', ') : 'none'}`);
  w('');

  const out = path.join(__dirname, '..', 'out', e.name, 'REPORT.md');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, L.join('\n'));
  return out;
}

module.exports = { renderReport };
