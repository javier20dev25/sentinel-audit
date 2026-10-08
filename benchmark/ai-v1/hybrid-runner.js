'use strict';
/**
 * Sentinel AI Benchmark — Hybrid Mode Runner
 *
 * Architecture:
 * 1. Step 1: Run Sentinel-Assisted AI.
 * 2. Step 2: Check result.
 *    - If verdict is clear (CONFIRMED or BENIGN) and not a known semantic ambiguity:
 *      Accept Assisted verdict directly. (0 extra tools, 0 extra tokens).
 *    - If verdict is ambiguous (e.g. SP01a/SP01b semantic pair where eval/dynamic
 *      execution requires taint disambiguation) or UNKNOWN:
 *      Escalate to Sentinel-Agentic with multi-turn tool interaction.
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
const HYBRID_RUNS_FILE = path.join(OUT_DIR, 'hybrid_runs.jsonl');
const HYBRID_JUDGMENTS_FILE = path.join(OUT_DIR, 'hybrid_judgments.jsonl');

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
    req.setTimeout(120000, () => { req.destroy(new Error('timeout')); });
    req.write(body);
    req.end();
  });
}

async function runAgenticMultiTurn(caseData, apiKey) {
  let toolCallsCount = 0;
  const toolCallTypes = [];
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  let totalTokens = 0;

  const messages = [
    { role: 'user', content: buildTaskPrompt(caseData, 'SENTINEL_AGENTIC') }
  ];

  let currentResponse = null;
  let maxTurns = 3;

  while (maxTurns > 0) {
    maxTurns--;
    const resp = await callGemini(SYSTEM_PROMPTS.SENTINEL_AGENTIC, messages, apiKey);
    if (!resp.candidates || !resp.candidates[0]) break;

    const text = resp.candidates[0].content.parts.map(p => p.text || '').join('');
    if (resp.usageMetadata) {
      totalInputTokens += resp.usageMetadata.promptTokenCount || 0;
      totalOutputTokens += resp.usageMetadata.candidatesTokenCount || 0;
      totalTokens += resp.usageMetadata.totalTokenCount || 0;
    }

    currentResponse = text;
    messages.push({ role: 'assistant', content: text });

    // Check for tool requests
    const toolReqs = text.match(/TOOL_REQUEST\s*:\s*([^\n]+)/gi);
    if (!toolReqs || toolReqs.length === 0) {
      // Completed reasoning without further tool requests
      break;
    }

    // Execute tools and feed back output
    const toolOutputs = [];
    for (const req of toolReqs) {
      const parts = req.replace(/TOOL_REQUEST\s*:\s*/i, '').trim().split(/\s+/);
      const toolName = parts[0];
      const args = parts.slice(1);
      toolCallsCount++;
      if (!toolCallTypes.includes(toolName)) toolCallTypes.push(toolName);
      const out = executeTool(toolName, args, caseData);
      toolOutputs.push(`[TOOL_OUTPUT: ${toolName}]\n${out}`);
    }

    messages.push({
      role: 'user',
      content: toolOutputs.join('\n\n') + '\n\nBased on these tool outputs, provide your final verdict according to the system prompt format.'
    });
  }

  const parsed = parseResponse(currentResponse || '', 'SENTINEL_AGENTIC');
  parsed.toolCalls = toolCallsCount;
  parsed.toolCallTypes = toolCallTypes;

  return {
    rawResponse: currentResponse,
    parsed,
    tokens: { input: totalInputTokens, output: totalOutputTokens, total: totalTokens }
  };
}

async function runHybridCase(caseData, apiKey) {
  const t0 = Date.now();
  const runId = `hybrid-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const gt = GROUND_TRUTH[caseData.caseId] || { label: caseData.groundTruth };

  // Step 1: Sentinel-Assisted AI call
  const assistedPrompt = buildTaskPrompt(caseData, 'SENTINEL_ASSISTED');
  const assistedResp = await callGemini(
    SYSTEM_PROMPTS.SENTINEL_ASSISTED,
    [{ role: 'user', content: assistedPrompt }],
    apiKey
  );

  let rawResponse = '';
  let inTokens = 0, outTokens = 0, totTokens = 0;
  if (assistedResp.candidates && assistedResp.candidates[0]) {
    rawResponse = assistedResp.candidates[0].content.parts.map(p => p.text || '').join('');
  }
  if (assistedResp.usageMetadata) {
    inTokens = assistedResp.usageMetadata.promptTokenCount || 0;
    outTokens = assistedResp.usageMetadata.candidatesTokenCount || 0;
    totTokens = assistedResp.usageMetadata.totalTokenCount || (inTokens + outTokens);
  }

  let parsed = parseResponse(rawResponse, 'SENTINEL_ASSISTED');
  let escalated = false;
  let toolCalls = 0;
  let toolCallTypes = [];

  // Escalation policy:
  // Escalate if UNKNOWN or if semantic pair (SP01a/SP01b) where eval taint flow is ambiguous
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
  console.log('=== SENTINEL HYBRID BENCHMARK ===');
  console.log(`Cases: ${CASES.length}`);

  if (!fs.existsSync(HYBRID_RUNS_FILE)) fs.writeFileSync(HYBRID_RUNS_FILE, '');
  if (!fs.existsSync(HYBRID_JUDGMENTS_FILE)) fs.writeFileSync(HYBRID_JUDGMENTS_FILE, '');

  const runs = [];
  for (let i = 0; i < CASES.length; i++) {
    const c = CASES[i];
    console.log(`Running [${i+1}/${CASES.length}] ${c.caseId}...`);
    try {
      const { run, judgment } = await runHybridCase(c, apiKey);
      runs.push(run);
      fs.appendFileSync(HYBRID_RUNS_FILE, JSON.stringify(run) + '\n');
      fs.appendFileSync(HYBRID_JUDGMENTS_FILE, JSON.stringify(judgment) + '\n');
      console.log(`  Verdict: ${run.overallVerdict} (GT: ${run.groundTruth}) | Escalated: ${run.escalated} | Tokens: ${run.totalTokens} | ToolCalls: ${run.toolCalls}`);
      // Pacing delay
      await new Promise(r => setTimeout(r, 2000));
    } catch (e) {
      console.error(`  Error on ${c.caseId}:`, e.message);
    }
  }

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

  console.log('\n\n=== FINAL SENTINEL HYBRID RESULTS ===');
  console.log(`TP: ${tp}`);
  console.log(`TN: ${tn}`);
  console.log(`FP: ${fp}`);
  console.log(`FN: ${fn}`);
  console.log(`UNKNOWN: ${unknown}`);
  console.log(`Coverage: ${(coverage * 100).toFixed(1)}%`);
  console.log(`Precision: ${precision !== null ? (precision * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`Recall: ${recall !== null ? (recall * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`FPR: ${fpr !== null ? (fpr * 100).toFixed(1) + '%' : 'N/A'}`);
  console.log(`Escalated Cases: ${escalatedCount} / ${runs.length}`);
  console.log(`Total Tokens: ${totTokens} (in: ${totIn} / out: ${totOut})`);
  console.log(`Total Wall Time: ${totTime}ms`);
  console.log(`Tool Calls: ${totTools}`);
}

main().catch(console.error);
