#!/usr/bin/env node
'use strict';
/**
 * Sentinel Audit Runner - a thin orchestrator.
 *
 * Principle: if CodeQL, Semgrep, Trivy, OSV, Bandit or ShellCheck already do it,
 * this runner does NOT implement it. It invokes, validates, normalises,
 * correlates, and refuses to let a zero look like a clean bill of health.
 *
 * Commands:
 *   preflight <repo...>        cheap readiness check, no analysis
 *   audit <repo>               full incremental pipeline
 *   report <expedienteDir>     render the markdown report
 *   doctor                     tool health + version table
 */
const fs = require('fs');
const path = require('path');
const { loadConfig, run, expand } = require('./lib/core');
const { preflight, checkToolHealth } = require('./workflow/preflight');
const { audit } = require('./workflow/audit');
const { renderReport } = require('./reports/expediente');
const { adjudicate, auditVerdict } = require('./correlate');

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (n, d) => { const i = argv.indexOf('--' + n); return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : (argv.includes('--' + n) ? true : d); };
const has = (n) => argv.includes('--' + n);
const positional = argv.slice(1).filter((a, i) => !a.startsWith('--') && !(i > 0 && argv[i].startsWith('--' + '') && false) && !isFlagValue(argv, a, i));
function isFlagValue(all, a, i) {
  const prev = all[i];
  if (!prev || !prev.startsWith('--')) return false;
  return !/^(true|false)$/.test(prev) && ['name', 'max-scope-files', 'ram'].includes(prev.slice(2));
}
const targets = positionalFor(argv);

function positionalFor(all) {
  const out = [];
  for (let i = 1; i < all.length; i++) {
    const a = all[i];
    if (a.startsWith('--')) {
      const name = a.slice(2);
      if (!['purple-full', 'skip-specialists', 'json', 'no-sca', 'quiet', 'keep-db'].includes(name)) i++; // consume value
      continue;
    }
    out.push(a);
  }
  return out;
}

const c = { dim: '\x1b[2m', red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m', cyn: '\x1b[36m', bold: '\x1b[1m', off: '\x1b[0m' };
const V = (verdict) => ({
  AUDIT_READY: c.grn, AUDIT_LIMITED: c.yel, SKIP: c.red,
  CLEAN_WITH_FULL_COVERAGE: c.grn, CLEAN_WITH_LIMITATIONS: c.yel, CANDIDATES_FOUND: c.cyn, PARTIAL_ANALYSIS: c.red,
  SUCCESS: c.grn, PARTIAL: c.yel, ERROR: c.red, UNSUPPORTED: c.red, SKIPPED: c.dim, NOT_APPLICABLE: c.dim,
  FULL: c.grn, LIMITED_COVERAGE: c.yel,
}[verdict] || '') + verdict + c.off;

async function main() {
  const { tools, policies } = loadConfig();

  if (cmd === 'doctor' || !cmd) {
    const h = checkToolHealth(tools);
    console.log(`${c.bold}Sentinel Audit Runner - doctor${c.off}\n`);
    for (const [k, v] of Object.entries(h)) {
      const ok = v.available ? c.grn + 'ok  ' + c.off : c.red + 'MISS' + c.off;
      let detail = v.version || v.reason || '';
      if (k === 'sentinel' && v.available) {
        // The pinned-input contract: the audit is only reproducible against a known, clean Purple.
        detail = `head ${v.head}${v.dirty ? c.yel + '  DIRTY WORKTREE' + c.off : c.dim + '  clean' + c.off}`;
      }
      console.log(`  ${k.padEnd(12)} ${ok}  ${String(detail).slice(0, 78)}`);
    }
    console.log(`\n  budget: ${policies.budget.totalWallClockMinutes}m wall clock, ` +
      Object.entries(policies.budget.perToolMinutes).map(([k, v]) => `${k}:${v}m`).join(' '));
    console.log(`  publication: push=${policies.publication.gitPush} pr=${policies.publication.createPullRequest} issue=${policies.publication.createIssue}`);
    console.log(`\n  ${c.dim}principle: this runner orchestrates. It does not re-implement detection.${c.off}`);
    return;
  }

  if (cmd === 'preflight') {
    if (!targets.length) { console.error('usage: preflight <repo...>'); process.exit(2); }
    const rows = [];
    for (const t of targets) {
      const p = preflight(t, { name: flag('name') });
      rows.push(p);
      console.log(`\n${c.bold}${p.name}${c.off}  ${V(p.verdict)}`);
      if (p.reasons.length) console.log(`   ${c.red}reasons${c.off}  ${p.reasons.join('; ')}`);
      if (p.limits.length) console.log(`   ${c.yel}limits${c.off}   ${p.limits.join('; ')}`);
      if (p.disclosure) console.log(`   disclosure  ${V(p.disclosure.verdict)} ${p.disclosure.files.join(',') || '(none)'}`);
      if (p.inv) console.log(`   surface     ${p.inv.production} production / ${p.inv.sourceFiles} source / ${(p.inv.nonShippedRatio * 100).toFixed(0)}% non-shipped  lang=${p.inv.mainLanguage}`);
      if (p.cost) console.log(`   cost        ~${p.cost.totalEstimateMinutes}m  ram=${p.cost.requiredRamMB}MB  ${p.cost.fitsBudget ? 'fits budget' : c.red + 'OVER BUDGET' + c.off}`);
    }
    if (has('json')) { console.log(JSON.stringify(rows, null, 2)); return; }
    const ready = rows.filter((r) => r.verdict === 'AUDIT_READY');
    console.log(`\n${c.bold}${ready.length}/${rows.length} AUDIT_READY${c.off}` +
      (ready.length ? `  -> ${ready.map((r) => r.name).join(', ')}` : '  (none worth the spend)'));
    return;
  }

  if (cmd === 'audit') {
    if (!targets.length) { console.error('usage: audit <repo> [--name x] [--skip-specialists] [--purple-full]'); process.exit(2); }
    const repo = targets[0];
    console.log(`${c.bold}Sentinel Audit Runner${c.off}  ${repo}`);
    const res = audit(repo, {
      name: typeof flag('name') === 'string' ? flag('name') : undefined,
      skipSpecialists: has('skip-specialists'),
      purpleFull: has('purple-full'),
      maxScopeFiles: Number(flag('max-scope-files', 40)),
      keepDb: has('keep-db'),
    });
    const e = res.expediente;
    if (e.skipped) { console.log(`\n${c.red}SKIPPED${c.off}: ${e.skipReasons.join('; ')}`); return; }
    const av = e.auditVerdict;
    console.log(`\n${c.bold}verdict${c.off}  ${V(av.verdict)}   ${c.dim}analysis:${c.off} ${V(av.analysisState)}   ${c.dim}canClaimClean:${c.off} ${av.canClaimClean}`);
    console.log(`  ${av.statement}`);
    console.log(`\n${c.bold}candidates${c.off} ${e.candidates.length}  ${c.dim}(corroborated by a dataflow/pattern authority)${c.off}`);
    for (const cand of e.candidates.slice(0, 20)) {
      console.log(`  ${c.cyn}${cand.candidateId}${c.off} ${cand.confidence.padEnd(6)} ${cand.tools.join('+').padEnd(28)} ${path.basename(cand.file)}:${cand.line || '?'}  ${cand.state}`);
    }
    if (e.observations && e.observations.length) {
      const ent = e.observations.filter((o) => o.purpleEntailed).length;
      console.log(`\n${c.dim}observations ${e.observations.length} breadth-only leads (not findings; ${ent} with purple ENTAILED)${c.off}`);
    }
    if (av.degradedTools.length) {
      console.log(`\n${c.yel}degraded tools${c.off}`);
      for (const d of av.degradedTools) console.log(`  ${d.tool.padEnd(12)} ${d.status.padEnd(11)} ${(d.reason || '').slice(0, 80)}`);
    }
    const report = renderReport(e);
    console.log(`\nexpediente  ${path.join(res.workDir, 'expediente.json')}`);
    console.log(`report      ${report}`);
    return;
  }

  if (cmd === 'report') {
    if (!targets.length) { console.error('usage: report <expedienteDir>'); process.exit(2); }
    const dir = targets[0];
    const e = JSON.parse(fs.readFileSync(path.join(dir, 'expediente.json'), 'utf8'));
    console.log(renderReport(e));
    return;
  }

  if (cmd === 'adjudicate') {
    if (!targets.length) { console.error('usage: adjudicate <expedienteDir> --candidate SAR-0001 --disposition OUT_OF_SCOPE --rationale "..."'); process.exit(2); }
    const dir = targets[0];
    const file = path.join(dir, 'expediente.json');
    const e = JSON.parse(fs.readFileSync(file, 'utf8'));
    const id = flag('candidate');
    const cand = (e.candidates || []).find((x) => x.candidateId === id);
    if (!cand) { console.error(`candidate ${id} not found. open candidates: ${(e.candidates || []).map((x) => x.candidateId).join(', ') || 'none'}`); process.exit(2); }
    const { policies } = loadConfig();
    const disp = flag('disposition');
    if (disp && !policies.dispositions.includes(disp)) {
      console.error(`unknown disposition "${disp}". allowed: ${policies.dispositions.join(', ')}`); process.exit(2);
    }
    adjudicate(cand, { disposition: disp, state: 'MANUALLY_VERIFIED', severity: flag('severity'), rationale: flag('rationale'), groundTruth: flag('ground-truth') });
    e.adjudications = (e.adjudications || []).concat([{ candidateId: cand.candidateId, at: new Date().toISOString(), by: 'human', disposition: cand.disposition, severity: cand.severity, rationale: cand.rationale }]);
    const av = auditVerdict(Object.values(e.tools).map((t) => ({ ...t, tool: t.tool })), (e.candidates || []).filter((x) => x.reportable !== false && !x.disposition.match(/^(BENIGN|FALSE_POSITIVE|OUT_OF_SCOPE|TOOLING_INTENT|ALREADY_MITIGATED|DUPLICATE)$/)));
    e.auditVerdict = av;
    fs.writeFileSync(file, JSON.stringify(e, null, 2));
    const report = renderReport(e);
    console.log(`${c.cyn}${cand.candidateId}${c.off} -> ${c.bold}${cand.disposition}${c.off}${cand.severity ? ' (' + cand.severity + ')' : ''}`);
    console.log(`  fingerprint ${cand.fingerprint}  reportable=${cand.reportable}`);
    console.log(`  rationale: ${cand.rationale || '(none recorded)'}`);
    console.log(`  audit verdict now: ${V(av.verdict)}   analysis=${V(av.analysisState)}   canClaimClean=${av.canClaimClean}`);
    console.log(`  report: ${report}`);
    return;
  }

  console.error('usage: sentinel-audit <preflight|audit|report|adjudicate|doctor> ...');
  process.exit(2);
}

main().catch((err) => { console.error(c.red + 'runner error:' + c.off, err && err.stack || err); process.exit(1); });
