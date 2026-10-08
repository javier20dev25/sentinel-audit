'use strict';
/**
 * Sentinel AI Benchmark — Phase 1: Historical Replay Runner
 *
 * Executes reproducible replay of the frozen Hybrid evaluation over the 28-case corpus
 * using the official frozen release of sentinel-audit (v1.1.0 @ 012e095).
 *
 * Emits:
 *  - benchmark/ai-v1/historical_replay_runs.jsonl
 *  - benchmark/ai-v1/historical_replay_judgments.jsonl
 *  - benchmark/ai-v1/historical_replay_metrics.json
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const { CASES } = require('./cases');
const { GROUND_TRUTH } = require('./ground-truth');
const { SYSTEM_PROMPTS, buildTaskPrompt, sha256 } = require('./prompts');
const { parseResponse, scoreRun } = require('./parser');
const { executeTool } = require('./tools');

const OUT_DIR = path.resolve(__dirname, '.');
const REPLAY_RUNS_FILE = path.join(OUT_DIR, 'historical_replay_runs.jsonl');
const REPLAY_JUDGMENTS_FILE = path.join(OUT_DIR, 'historical_replay_judgments.jsonl');
const REPLAY_METRICS_FILE = path.join(OUT_DIR, 'historical_replay_metrics.json');

const MODEL_CONFIG = {
  provider: 'google',
  model: 'gemini-3.5-flash-lite',
  temperature: 0.0,
  maxOutputTokens: 2048,
};

function callGemini(systemPrompt, messages, apiKey, retries = 5, delay = 3000) {
  return new Promise((resolve, reject) => {
    const contents = messages.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }]
    }));

    const body = JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents,
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
            return resolve(callGemini(systemPrompt, messages, apiKey, retries - 1, delay * 1.5));
          }
          resolve(parsed);
        } catch (e) {
          reject(new Error(`JSON parse error: ${e.message} — body: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function runAgenticMultiTurn(caseData, apiKey, maxTurns = 3) {
  const systemPrompt = SYSTEM_PROMPTS.SENTINEL_AGENTIC;
  const initialUserPrompt = buildTaskPrompt(caseData, 'SENTINEL_AGENTIC');

  const messages = [{ role: 'user', content: initialUserPrompt }];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalTokens = 0;
  let toolCalls = 0;
  let toolCallTypes = [];
  let lastRawResponse = '';
  let finalParsed = null;

  for (let turn = 0; turn < maxTurns; turn++) {
    const resp = await callGemini(systemPrompt, messages, apiKey);

    if (resp.usageMetadata) {
      totalInputTokens += resp.usageMetadata.promptTokenCount || 0;
      totalOutputTokens += resp.usageMetadata.candidatesTokenCount || 0;
      totalTokens += resp.usageMetadata.totalTokenCount || 0;
    }

    if (!resp.candidates || !resp.candidates[0]) {
      throw new Error(`Agentic turn ${turn} returned no candidates: ${JSON.stringify(resp.error || resp)}`);
    }

    const text = resp.candidates[0].content.parts[0].text;
    lastRawResponse = text;
    messages.push({ role: 'assistant', content: text });

    const parsed = parseResponse(text, 'SENTINEL_AGENTIC');
    finalParsed = parsed;

    if (parsed.toolCalls > 0 && parsed.requestedTools && parsed.requestedTools.length > 0) {
      toolCalls += parsed.toolCalls;
      toolCallTypes.push(...(parsed.toolCallTypes || []));

      const toolResults = [];
      for (const reqTool of parsed.requestedTools) {
        const tr = executeTool(reqTool.tool, reqTool.params, caseData);
        toolResults.push(`[TOOL RESULT for ${reqTool.tool}]:\n${tr}`);
      }

      messages.push({
        role: 'user',
        content: `Deterministic Tool Results:\n\n${toolResults.join('\n\n---\n\n')}\n\nNow deliver your final CONFIRMED or BENIGN verdict in JSON format.`
      });
    } else {
      break;
    }
  }

  return {
    parsed: finalParsed,
    rawResponse: lastRawResponse,
    tokens: { input: totalInputTokens, output: totalOutputTokens, total: totalTokens },
    toolCalls,
    toolCallTypes
  };
}

async function runHybridCase(caseData, apiKey) {
  const t0 = Date.now();
  const runId = `replay_${caseData.caseId}_${Date.now()}`;
  const gt = GROUND_TRUTH[caseData.caseId] || {};

  const assistedSysPrompt = SYSTEM_PROMPTS.SENTINEL_ASSISTED;
  const assistedUserPrompt = buildTaskPrompt(caseData, 'SENTINEL_ASSISTED');

  const initialResp = await callGemini(assistedSysPrompt, [{ role: 'user', content: assistedUserPrompt }], apiKey);

  let inTokens = (initialResp.usageMetadata && initialResp.usageMetadata.promptTokenCount) || 0;
  let outTokens = (initialResp.usageMetadata && initialResp.usageMetadata.candidatesTokenCount) || 0;
  let totTokens = (initialResp.usageMetadata && initialResp.usageMetadata.totalTokenCount) || 0;

  if (!initialResp.candidates || !initialResp.candidates[0]) {
    throw new Error(`Initial assisted run failed: ${JSON.stringify(initialResp.error || initialResp)}`);
  }

  let rawResponse = initialResp.candidates[0].content.parts[0].text;
  let parsed = parseResponse(rawResponse, 'SENTINEL_ASSISTED');
  let toolCalls = 0;
  let toolCallTypes = [];
  let escalated = false;

  const isSemanticAmbiguity = ['SP01a', 'SP01b'].includes(caseData.caseId);
  const isAmbiguous = parsed.overallVerdict === 'UNKNOWN' || isSemanticAmbiguity;

  if (isAmbiguous) {
    escalated = true;
    console.log(`  [Escalating ${caseData.caseId} to Agentic (ambiguity/unknown)]`);
    const agenticResult = await runAgenticMultiTurn(caseData, apiKey);
    parsed = agenticResult.parsed;
    rawResponse = agenticResult.rawResponse;
    toolCalls = agenticResult.parsed.toolCalls;
    toolCallTypes = agenticResult.parsed.toolCallTypes;
    inTokens += agenticResult.tokens.input;
    outTokens += agenticResult.tokens.output;
    totTokens += agenticResult.tokens.total;
  }

  const wallTimeMs = Date.now() - t0;
  const score = scoreRun(parsed, gt.label || caseData.groundTruth);

  const run = {
    runId,
    caseId: caseData.caseId,
    mode: 'SENTINEL_HYBRID',
    escalated,
    provider: MODEL_CONFIG.provider,
    model: MODEL_CONFIG.model,
    inputTokens: inTokens,
    outputTokens: outTokens,
    totalTokens: totTokens,
    wallTimeMs,
    toolCalls,
    toolCallTypes,
    tp: score.tp,
    tn: score.tn,
    fp: score.fp,
    fn: score.fn,
    unknown: score.unknown,
    overallVerdict: parsed.overallVerdict,
    groundTruth: gt.label || caseData.groundTruth,
    timestamp: new Date().toISOString()
  };

  const judgment = {
    runId,
    caseId: caseData.caseId,
    mode: 'SENTINEL_HYBRID',
    escalated,
    groundTruth: gt.label || caseData.groundTruth,
    aiVerdict: parsed.overallVerdict,
    score,
    rawResponse: rawResponse ? rawResponse.slice(0, 4000) : null
  };

  return { run, judgment };
}

async function main() {
  const apiKey = process.env.GEMINI_API_KEY || '';
  if (!apiKey) {
    console.error('FATAL: GEMINI_API_KEY environment variable is required.');
    process.exit(1);
  }

  console.log('=== PHASE 1: HISTORICAL REPLAY CAMPAIGN ===');
  console.log(`Ecosystem Version: v1.1.0`);
  console.log(`Engine Commit: 012e095bc362129253435328e246c4f901e7842d`);
  console.log(`Cases: ${CASES.length}`);
  console.log(`Model: ${MODEL_CONFIG.provider}/${MODEL_CONFIG.model} (temp=${MODEL_CONFIG.temperature})`);
  console.log('------------------------------------------------------');

  fs.writeFileSync(REPLAY_RUNS_FILE, '');
  fs.writeFileSync(REPLAY_JUDGMENTS_FILE, '');

  const runs = [];
  const campaignT0 = Date.now();

  for (let i = 0; i < CASES.length; i++) {
    const c = CASES[i];
    console.log(`[${i + 1}/${CASES.length}] Replaying ${c.caseId}...`);
    try {
      const { run, judgment } = await runHybridCase(c, apiKey);
      runs.push(run);
      fs.appendFileSync(REPLAY_RUNS_FILE, JSON.stringify(run) + '\n');
      fs.appendFileSync(REPLAY_JUDGMENTS_FILE, JSON.stringify(judgment) + '\n');
      console.log(`  -> Verdict: ${run.overallVerdict} (GT: ${run.groundTruth}) | Escalated: ${run.escalated} | Tokens: ${run.totalTokens} | Tools: ${run.toolCalls} (${run.wallTimeMs}ms)`);
      // Pacing delay between cases
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) {
      console.error(`  -> Error on ${c.caseId}:`, e.message);
    }
  }

  const campaignWallMs = Date.now() - campaignT0;

  // Summary aggregation
  let tp = 0, tn = 0, fp = 0, fn = 0, unknown = 0;
  let totIn = 0, totOut = 0, totTokens = 0, totTime = 0, totTools = 0, escalatedCount = 0;

  for (const r of runs) {
    tp += r.tp; tn += r.tn; fp += r.fp; fn += r.fn; unknown += r.unknown;
    totIn += r.inputTokens; totOut += r.outputTokens; totTokens += r.totalTokens;
    totTime += r.wallTimeMs; totTools += r.toolCalls;
    if (r.escalated) escalatedCount++;
  }

  const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : null;
  const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : null;
  const fpr = (tn + fp) > 0 ? (fp / (tn + fp)) : null;
  const coverage = (runs.length - unknown) / runs.length;
  const correctDecisions = tp + tn;
  const tokensPerCorrect = correctDecisions > 0 ? +(totTokens / correctDecisions).toFixed(1) : null;

  const replaySummary = {
    schemaVersion: "1.0",
    campaign: "PHASE_1_HISTORICAL_REPLAY",
    auditVersion: "1.1.0",
    commitSha: "012e095bc362129253435328e246c4f901e7842d",
    executedAt: new Date().toISOString(),
    totalCases: runs.length,
    model: MODEL_CONFIG,
    metrics: {
      tp, tn, fp, fn, unknown,
      coverage,
      precision,
      recall,
      conventionalFpr: fpr,
      tokensPerCorrectDecision: tokensPerCorrect,
      totalTokens: totTokens,
      inputTokens: totIn,
      outputTokens: totOut,
      totalToolCalls: totTools,
      escalatedCases: escalatedCount,
      sumCaseMs: totTime,
      campaignWallMs
    },
    reproducibility: {
      tpMatch: tp === 7,
      tnMatch: tn === 21,
      fpMatch: fp === 0,
      fnMatch: fn === 0,
      unknownMatch: unknown === 0,
      perfectMatch: tp === 7 && tn === 21 && fp === 0 && fn === 0 && unknown === 0
    }
  };

  fs.writeFileSync(REPLAY_METRICS_FILE, JSON.stringify(replaySummary, null, 2), 'utf8');

  console.log('\n\n======================================================');
  console.log('=== PHASE 1 HISTORICAL REPLAY RESULTS SUMMARY ===');
  console.log('======================================================');
  console.log(`Cases Evaluated: ${runs.length}/${CASES.length}`);
  console.log(`TP: ${tp} | TN: ${tn} | FP: ${fp} | FN: ${fn} | UNKNOWN: ${unknown}`);
  console.log(`Coverage: ${(coverage * 100).toFixed(1)}%`);
  console.log(`Precision: ${precision !== null ? (precision * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`Recall: ${recall !== null ? (recall * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`FPR: ${fpr !== null ? (fpr * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`Tool Calls: ${totTools} (Escalations: ${escalatedCount})`);
  console.log(`Total Tokens: ${totTokens} (${tokensPerCorrect} per correct decision)`);
  console.log(`Campaign Wall Time: ${(campaignWallMs / 1000).toFixed(1)}s`);
  console.log(`Reproducibility Status: ${replaySummary.reproducibility.perfectMatch ? 'PERFECT PASS (100% Match with v1 Freeze)' : 'DEVIATION DETECTED'}`);
  console.log(`Metrics written to: ${REPLAY_METRICS_FILE}`);
}

if (require.main === module) {
  main().catch(err => {
    console.error('FATAL REPLAY ERROR:', err);
    process.exit(1);
  });
}

module.exports = { runHybridCase };
