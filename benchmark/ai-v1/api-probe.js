'use strict';
/**
 * Sentinel AI Benchmark — API connectivity probe
 *
 * Tests Anthropic API access and checks what AI inference is available.
 * Also checks if GOOGLE_API_KEY / Gemini is available as alternative.
 */

const https = require('https');
const http = require('http');

function tryAnthropic(apiKey) {
  return new Promise((resolve) => {
    if (!apiKey || apiKey.length < 10) {
      return resolve({ available: false, error: 'No API key set' });
    }
    const body = JSON.stringify({
      model: 'claude-haiku-4-5',
      max_tokens: 50,
      messages: [{ role: 'user', content: 'Reply with the word BENCHMARK only.' }],
    });
    const opts = {
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          if (j.content && j.content[0]) {
            resolve({ available: true, model: j.model, usage: j.usage, text: j.content[0].text });
          } else {
            resolve({ available: false, error: j.error ? j.error.message : 'no content', status: res.statusCode });
          }
        } catch (e) { resolve({ available: false, error: e.message }); }
      });
    });
    req.on('error', e => resolve({ available: false, error: e.message }));
    req.setTimeout(15000, () => { req.destroy(); resolve({ available: false, error: 'timeout' }); });
    req.write(body); req.end();
  });
}

function tryGemini(apiKey) {
  return new Promise((resolve) => {
    if (!apiKey || apiKey.length < 10) {
      return resolve({ available: false, error: 'No API key set' });
    }
    const body = JSON.stringify({
      contents: [{ parts: [{ text: 'Reply with the word BENCHMARK only.' }] }],
    });
    const path = `/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
    const opts = {
      hostname: 'generativelanguage.googleapis.com', path, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    };
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          if (j.candidates && j.candidates[0]) {
            resolve({ available: true, model: 'gemini-2.0-flash', usage: j.usageMetadata,
                      text: j.candidates[0].content.parts[0].text });
          } else {
            resolve({ available: false, error: j.error ? j.error.message : 'no candidates', status: res.statusCode });
          }
        } catch (e) { resolve({ available: false, error: e.message }); }
      });
    });
    req.on('error', e => resolve({ available: false, error: e.message }));
    req.setTimeout(15000, () => { req.destroy(); resolve({ available: false, error: 'timeout' }); });
    req.write(body); req.end();
  });
}

async function main() {
  const anthropicKey = process.env.ANTHROPIC_API_KEY || '';
  const geminiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY || '';

  console.log('=== API Connectivity Probe ===\n');
  console.log(`ANTHROPIC_API_KEY present: ${anthropicKey.length > 0} (len=${anthropicKey.length})`);
  console.log(`GOOGLE_API_KEY present: ${geminiKey.length > 0} (len=${geminiKey.length})`);
  console.log('');

  const [anthropicResult, geminiResult] = await Promise.all([
    tryAnthropic(anthropicKey),
    tryGemini(geminiKey),
  ]);

  console.log('Anthropic:', JSON.stringify(anthropicResult, null, 2));
  console.log('Gemini:', JSON.stringify(geminiResult, null, 2));
}

main().catch(e => { console.error(e); process.exit(1); });
