'use strict';
/**
 * Sentinel AI Benchmark — Runner (Wave-based, max 8 concurrent workers)
 *
 * Uses Google Gemini API (gemini-2.5-flash) with deterministic generationConfig
 * and real usageMetadata (promptTokenCount, candidatesTokenCount, totalTokenCount).
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const { CASES } = require('./cases');
const { GROUND_TRUTH } = require('./ground-truth');
const { SYSTEM_PROMPTS, SYSTEM_PROMPT_HASHES, buildTaskPrompt, sha256 } = require('./prompts');
const { parseResponse, scoreRun } = require('./parser');

const OUT_DIR = path.resolve(__dirname, '.');
const RUNS_FILE = path.join(OUT_DIR, 'runs.jsonl');
const JUDGMENTS_FILE = path.join(OUT_DIR, 'judgments.jsonl');

const MODEL_CONFIG = {
  provider: 'google',
  model: 'gemini-3.5-flash-lite',
  temperature: 0.0,
  maxOutputTokens: 2048,
};

const MAX_WORKERS = 2;

function callGemini(systemPrompt, userPrompt, apiKey, retries = 5, delay = 3000) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      systemInstruction: {
        parts: [{ text: systemPrompt }]
      },
      contents: [{
        role: 'user',
        parts: [{ text: userPrompt }]
      }],
      generationConfig: {
        temperature: MODEL_CONFIG.temperature,
        maxOutputTokens: MODEL_CONFIG.maxOutputTokens,
      }
    });

    const opts = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/${MODEL_CONFIG.model}:generateContent?key=${apiKey}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', async () => {
        try {
          const parsed = JSON.parse(data);
          if ((res.statusCode === 503 || res.statusCode === 429) && retries > 0) {
            console.log(`[RateLimit/Retry ${retries}] HTTP ${res.statusCode}, waiting ${delay}ms...`);
            await new Promise(r => setTimeout(r, delay));
            return resolve(callGemini(systemPrompt, userPrompt, apiKey, retries - 1, delay * 1.5));
          }
          resolve(parsed);
        } catch (e) {
          reject(new Error(`JSON parse error: ${e.message} — body: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(120000, () => { req.destroy(new Error('timeout')); });
    req.write(body);
    req.end();
  });
}

async function runCase(caseData, mode, apiKey) {
  const t0 = Date.now();
  const runId = `run-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const gt = GROUND_TRUTH[caseData.caseId] || { label: caseData.groundTruth };

  const systemPrompt = SYSTEM_PROMPTS[mode];
  let taskPrompt;
  try {
    taskPrompt = buildTaskPrompt(caseData, mode);
  } catch (e) {
    taskPrompt = `Error building prompt: ${e.message}`;
  }

  const promptHash = sha256(taskPrompt);
  let rawResponse = null;
  let inputTokens = null;
  let outputTokens = null;
  let totalTokens = null;
  let tokenMeasurement = 'UNAVAILABLE';
  let error = null;

  try {
    const resp = await callGemini(systemPrompt, taskPrompt, apiKey);
    if (resp.error) {
      error = resp.error.message || JSON.stringify(resp.error);
    } else {
      if (resp.candidates && resp.candidates[0] && resp.candidates[0].content && resp.candidates[0].content.parts) {
        rawResponse = resp.candidates[0].content.parts.map(p => p.text || '').join('');
      }
      if (resp.usageMetadata) {
        inputTokens = resp.usageMetadata.promptTokenCount || null;
        outputTokens = resp.usageMetadata.candidatesTokenCount || null;
        totalTokens = resp.usageMetadata.totalTokenCount || ((inputTokens || 0) + (outputTokens || 0));
        tokenMeasurement = 'PASS';
      }
    }
  } catch (e) {
    error = e.message;
  }

  const wallTimeMs = Date.now() - t0;
  const parsed = parseResponse(rawResponse || '', mode);
  const score = scoreRun(parsed, gt.label || caseData.groundTruth);

  const run = {
    runId,
    caseId: caseData.caseId,
    mode,
    provider: MODEL_CONFIG.provider,
    model: MODEL_CONFIG.model,
    modelVersion: 'gemini-2.5-flash-001',
    temperature: MODEL_CONFIG.temperature,
    maxTokens: MODEL_CONFIG.maxOutputTokens,
    systemPromptHash: SYSTEM_PROMPT_HASHES[mode],
    taskPromptHash: promptHash,
    timestamp: new Date().toISOString(),
    inputTokens,
    outputTokens,
    totalTokens,
    wallTimeMs,
    toolCalls: parsed.toolCalls,
    toolCallTypes: parsed.toolCallTypes,
    tp: score.tp,
    tn: score.tn,
    fp: score.fp,
    fn: score.fn,
    unknown: score.unknown,
    overallVerdict: parsed.overallVerdict,
    confirmedCount: parsed.confirmed,
    falsePositiveCount: parsed.falsePositive,
    unknownCount: parsed.unknown,
    findingsCount: parsed.findings.length,
    actualTokenMeasurement: tokenMeasurement,
    error: error || null,
  };

  const judgment = {
    runId,
    caseId: caseData.caseId,
    mode,
    groundTruth: gt.label || caseData.groundTruth,
    aiVerdict: parsed.overallVerdict,
    score,
    findings: parsed.findings,
    rawResponse: rawResponse ? rawResponse.slice(0, 4000) : null,
    error: error || null,
  };

  return { run, judgment };
}

async function runWave(tasks, apiKey, waveLabel = '') {
  const results = [];
  for (let i = 0; i < tasks.length; i += MAX_WORKERS) {
    const batch = tasks.slice(i, i + MAX_WORKERS);
    console.log(`\n[WAVE ${waveLabel}] Running ${batch.length} workers: ${batch.map(t => `${t.caseId}/${t.mode}`).join(', ')}`);
    const batchResults = await Promise.all(
      batch.map(({ caseData, mode }) => runCase(caseData, mode, apiKey).catch(e => ({
        run: { caseId: caseData.caseId, mode, error: e.message, tp:0,tn:0,fp:0,fn:0,unknown:1,
               overallVerdict:'UNKNOWN', actualTokenMeasurement:'UNAVAILABLE',
               timestamp: new Date().toISOString() },
        judgment: { caseId: caseData.caseId, mode, groundTruth: caseData.groundTruth,
                    aiVerdict:'UNKNOWN', score:{tp:0,tn:0,fp:0,fn:0,unknown:1},
                    findings:[], rawResponse:null, error: e.message },
      })))
    );
    for (const r of batchResults) {
      console.log(`  ${r.run.caseId}/${r.run.mode}: verdict=${r.run.overallVerdict} ` +
                  `tp=${r.run.tp} tn=${r.run.tn} fp=${r.run.fp} fn=${r.run.fn} ` +
                  `tokens=${r.run.totalTokens || 'N/A'} (in:${r.run.inputTokens}/out:${r.run.outputTokens}) ms=${r.run.wallTimeMs}`);
      fs.appendFileSync(RUNS_FILE, JSON.stringify(r.run) + '\n');
      fs.appendFileSync(JUDGMENTS_FILE, JSON.stringify(r.judgment) + '\n');
    }
    results.push(...batchResults);
    // Pacing delay between batches to respect RPM rate limits
    await new Promise(r => setTimeout(r, 1500));
  }
  return results;
}

function computeSummary(runs) {
  const byMode = {};
  for (const r of runs) {
    if (!byMode[r.mode]) {
      byMode[r.mode] = { tp:0,tn:0,fp:0,fn:0,unknown:0,
                         totalTokens:0,inputTokens:0,outputTokens:0,wallTimeMs:0,toolCalls:0,runs:0,
                         tokenMeasurementAvail:0 };
    }
    const m = byMode[r.mode];
    m.tp += r.tp || 0; m.tn += r.tn || 0;
    m.fp += r.fp || 0; m.fn += r.fn || 0;
    m.unknown += r.unknown || 0;
    m.inputTokens += r.inputTokens || 0;
    m.outputTokens += r.outputTokens || 0;
    m.totalTokens += r.totalTokens || 0;
    m.wallTimeMs += r.wallTimeMs || 0;
    m.toolCalls += r.toolCalls || 0;
    m.runs++;
    if (r.actualTokenMeasurement === 'PASS') m.tokenMeasurementAvail++;
  }

  const result = {};
  for (const [mode, m] of Object.entries(byMode)) {
    const precision = m.tp + m.fp > 0 ? (m.tp / (m.tp + m.fp)) : null;
    const recall = m.tp + m.fn > 0 ? (m.tp / (m.tp + m.fn)) : null;
    const fpr = m.tn + m.fp > 0 ? (m.fp / (m.tn + m.fp)) : null;
    const fnr = m.tp + m.fn > 0 ? (m.fn / (m.tp + m.fn)) : null;
    const confirmedPer1kTokens = m.totalTokens > 0 ? ((m.tp / m.totalTokens) * 1000) : null;
    result[mode] = {
      runs: m.runs,
      tp: m.tp, tn: m.tn, fp: m.fp, fn: m.fn, unknown: m.unknown,
      precision: precision !== null ? +precision.toFixed(4) : null,
      recall: recall !== null ? +recall.toFixed(4) : null,
      fpr: fpr !== null ? +fpr.toFixed(4) : null,
      fnr: fnr !== null ? +fnr.toFixed(4) : null,
      inputTokens: m.inputTokens,
      outputTokens: m.outputTokens,
      totalTokens: m.totalTokens,
      avgTokensPerRun: m.runs > 0 ? Math.round(m.totalTokens / m.runs) : null,
      totalWallTimeMs: m.wallTimeMs,
      toolCalls: m.toolCalls,
      confirmedPer1kTokens: confirmedPer1kTokens !== null ? +confirmedPer1kTokens.toFixed(4) : null,
      tokenMeasurementPass: m.tokenMeasurementAvail,
      actualTokenMeasurement: m.tokenMeasurementAvail > 0 ? 'PASS' : 'UNAVAILABLE',
    };
  }
  return result;
}

async function main() {
  const args = process.argv.slice(2);
  const apiKey = process.env.GEMINI_API_KEY || '';

  const runAll = args.includes('--all');
  const modeArg = args.find(a => a.startsWith('--mode=')) || args[args.indexOf('--mode') + 1];
  const modesToRun = runAll
    ? ['AI_ALONE', 'SENTINEL_ASSISTED', 'SENTINEL_AGENTIC']
    : [modeArg || 'AI_ALONE'];

  const casesArg = args.find(a => a.startsWith('--cases='));
  let caseFilter = null;
  if (casesArg) {
    caseFilter = new Set(casesArg.replace('--cases=','').split(',').map(s => s.trim()));
  }

  let caseList = CASES;
  if (caseFilter) caseList = CASES.filter(c => caseFilter.has(c.caseId));

  console.log(`\n=== SENTINEL AI BENCHMARK v1 ===`);
  console.log(`Modes: ${modesToRun.join(', ')}`);
  console.log(`Cases: ${caseList.map(c => c.caseId).join(', ')} (${caseList.length})`);
  console.log(`Model: ${MODEL_CONFIG.provider}/${MODEL_CONFIG.model} temp=${MODEL_CONFIG.temperature}`);
  console.log(`Max workers: ${MAX_WORKERS}`);
  console.log(`Output: ${OUT_DIR}`);

  if (!fs.existsSync(RUNS_FILE)) fs.writeFileSync(RUNS_FILE, '');
  if (!fs.existsSync(JUDGMENTS_FILE)) fs.writeFileSync(JUDGMENTS_FILE, '');

  const allRuns = [];
  let waveNum = 0;

  const modeQueues = {};
  for (const mode of modesToRun) {
    modeQueues[mode] = caseList.map(c => ({ caseData: c, mode }));
  }

  const totalTasks = modesToRun.reduce((s, m) => s + modeQueues[m].length, 0);
  let done = 0;

  while (modesToRun.some(m => modeQueues[m].length > 0)) {
    waveNum++;
    const batch = [];
    const slots = { AI_ALONE: 4, SENTINEL_ASSISTED: 2, SENTINEL_AGENTIC: 2 };
    for (const mode of modesToRun) {
      const s = slots[mode] || 2;
      const pulled = modeQueues[mode].splice(0, s);
      batch.push(...pulled);
    }
    if (!batch.length) break;

    const results = await runWave(batch, apiKey, String(waveNum));
    allRuns.push(...results.map(r => r.run));
    done += batch.length;
    console.log(`\n[Progress] ${done}/${totalTasks} tasks complete`);
  }

  const summary = computeSummary(allRuns);
  const summaryOut = {
    schemaVersion: '1.0',
    benchmarkId: 'sentinel-ai-v1',
    completedAt: new Date().toISOString(),
    totalRuns: allRuns.length,
    statisticalQuality: 'LOW_MEDIUM_CONTROLLED_ENGINEERING_STUDY',
    corpus: { malicious: 6, benign: 20, semanticPair: 2, total: 28 },
    model: MODEL_CONFIG,
    systemPromptHashes: SYSTEM_PROMPT_HASHES,
    results: summary,
    benchmarkComplete: allRuns.length === totalTasks ? 'YES' : 'NO',
  };

  fs.writeFileSync(path.join(OUT_DIR, 'summary.json'), JSON.stringify(summaryOut, null, 2));

  console.log('\n\n=== BENCHMARK RESULTS ===');
  for (const [mode, s] of Object.entries(summary)) {
    console.log(`\n${mode}:`);
    console.log(`  TP=${s.tp} TN=${s.tn} FP=${s.fp} FN=${s.fn} UNKNOWN=${s.unknown}`);
    console.log(`  precision=${s.precision !== null ? (s.precision*100).toFixed(1)+'%' : 'N/A'}`);
    console.log(`  recall=${s.recall !== null ? (s.recall*100).toFixed(1)+'%' : 'N/A'}`);
    console.log(`  FPR=${s.fpr !== null ? (s.fpr*100).toFixed(1)+'%' : 'N/A'}`);
    console.log(`  FNR=${s.fnr !== null ? (s.fnr*100).toFixed(1)+'%' : 'N/A'}`);
    console.log(`  inputTokens=${s.inputTokens} outputTokens=${s.outputTokens} totalTokens=${s.totalTokens}`);
    console.log(`  avgTokensPerRun=${s.avgTokensPerRun}`);
    console.log(`  wallTime_total=${s.totalWallTimeMs}ms`);
    console.log(`  toolCalls=${s.toolCalls}`);
    console.log(`  confirmedPer1kTokens=${s.confirmedPer1kTokens}`);
    console.log(`  ACTUAL_TOKEN_MEASUREMENT=${s.actualTokenMeasurement}`);
  }
  console.log(`\nBENCHMARK_COMPLETE = ${summaryOut.benchmarkComplete}`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
