# Sentinel Cloud — repository scan contract (design, not implemented)

Status: **design grounded in verified source.** Nothing described here is built yet.
Every convention below was read from the code, not assumed. Line citations refer to
`C:\Users\sleyt\sentinel-cloud` at the time of audit.

This document exists so that the new capability reuses what Sentinel Cloud already
does instead of creating a second, parallel convention.

## 1. Why a new capability is needed

`POST /api/scan/remote` (`src/app/api/scan/remote/route.ts:57`) accepts a single npm
`package.json` manifest, format whitelist `['npm']`, max 262144 bytes (`:97-105`).
It answers a supply-chain question about one package. It cannot answer "what is in
this repository", which is what an orchestrated audit needs.

An audit also needs a stable envelope carrying execution completeness and coverage,
which the manifest route does not return.

## 2. Existing conventions that must be reused

| Concern | Existing convention | Source |
|---|---|---|
| Job status | `PENDING`, `PROCESSING`, `COMPLETED`, `FAILED`, `CANCELLED` | `job_status_enum` `supabase/migrations/20260427010000_add_scan_jobs.sql:7`; `CANCELLED` added `20260916000001_flip1_a1_add_cancelled_enum.sql:6` |
| Lease | `claimed_until TIMESTAMPTZ` (2 min) + `metadata.worker_lease` UUID (JSONB key, not a column) | `20260703000012:9`, `20260703000013:43-48` |
| Claim | `FOR UPDATE SKIP LOCKED`, `scan_priority` then `created_at` | `20260703000013:28-37` |
| Terminal write | lease-guarded, returns `won`; publish verdict only if won | `packages/worker/queue/job-queue.js:63-88` |
| Re-scan same target | `cancel_and_create_scan_job` reactivates the row | `20260917000003_p0_2_tenant_scoped_cancel_create_rpc.sql:31` |
| Auth resolution | session wins over bearer | `src/lib/auth/intelligence-auth.ts:108-110` |
| Entitlement | `getEffectivePlan(subjectId)` then capability check then quota | `src/lib/plan-gate.ts:189-196`, `src/lib/usage-meter.ts:15-29` |
| Error codes | `code: 'NO_ACTIVE_SUBSCRIPTION'` (403), `code: 'PULSOS_EXHAUSTED'` (429) | `intelligence-auth.ts:33`, `scan/remote/route.ts:117` |
| Writes | Service Role client; remote RLS is SELECT-only | `scan/pr/route.ts:339` |

The worker is already an Express process that also consumes the queue
(`packages/worker/index.js:53-59` health, `:117` dequeue, `:218-223` engine call).
The intake path is the only missing piece.

## 3. Proposed surface

Job-based, because the engine is expensive and the existing queue already provides
the machinery. Not versioned, to match the current unversioned `/api/*` surface;
introducing `/api/v1` would fork the convention.

```
POST /api/scan/repository          multipart or gzip body
  -> 202 { scanId, status: 'PENDING' }

GET  /api/scan/repository/:scanId
  -> 200 { scanId, status, createdAt, updatedAt, error? }

GET  /api/scan/repository/:scanId/result
  -> 200 { result envelope }        only when COMPLETED
```

All three require `Authorization: Bearer sntl_...` and return the same status codes
already in use: 401, 403 `NO_ACTIVE_SUBSCRIPTION`, 429 `PULSOS_EXHAUSTED`, 503 busy.

## 4. Result envelope

Must satisfy Audit while exposing nothing about engine internals.

```json
{
  "scanId": "...",
  "status": "COMPLETED",
  "engine": { "revision": "...", "hash": "..." },
  "executionComplete": true,
  "coverageKnown": false,
  "coverageUnknown": true,
  "filesScanned": 1284,
  "filesFailed": 0,
  "alertsSeen": 41,
  "alertsEnrichFailed": 0,
  "signals": [ ... ]
}
```

`coverageKnown` stays `false` until the engine exposes parsed-file counters. That
is already the engine's real state (`adapters/index.js:131-136` in Audit) and must
not be reported as `true` to make the product look better.

Signals are returned to the authenticated caller and not cached in a shared table.

## 5. Archive handling security

The upload is untrusted arbitrary code. Requirements:

- Hard caps: compressed size, extracted bytes, file count, path depth, entry count.
- Reject absolute paths, `..` traversal, symlinks, hardlinks, device entries.
- Refuse entries whose resolved path escapes the extraction root, checked after
  every normalization step, not once at the start.
- Extraction and scan run under distinct timeouts; a timeout is a `FAILED` job with
  a reason, never a silent success.
- Extract into a fresh directory outside any web root; never reuse a previous job's
  directory.
- No repository script execution, no lifecycle hooks, no inherited credentials.
- The worker already disposes with `fs.rmSync` (`packages/worker/index.js:233`);
  the new path must do the same on COMPLETED, FAILED, TIMEOUT and CANCELLED.

## 6. Privacy and retention

- Cloud mode is opt-in. Local mode never transmits source.
- Retention: destroy the archive and the extracted workspace when the job reaches a
  terminal state, unless an explicit retention policy is configured.
- Never send: git credentials, SSH keys, environment files, credential files.
- Do NOT auto-exclude security-relevant files such as `.github/`, `SECURITY.md`,
  manifests, lockfiles or config files. Excluding them would silently blind the scan.
- Document exactly what is sent, when, and when it is destroyed.

## 7. Prerequisites that block implementation

These are defects found during contract verification. The new endpoint must not be
built on top of them.

1. **`api_tokens` throws on Vercel.** `src/lib/local-db.ts:26-31` raises when
   `VERCEL === '1'`; `src/lib/auth/api-tokens.ts:112` calls `getDb()` unguarded. Every
   bearer route therefore fails with 500 instead of 401, and token minting is
   impossible on Vercel. Tokens must move to Supabase (or another production store)
   before any new authenticated route is added.
2. **`scan_jobs` is frozen mid-redesign.** `docs/design/scan_jobs_schema_contract_audit.md:232-242`
   records a freeze and a queued end state (`user_id UUID NULL`, new `source` column);
   the exit gate is 3/6 green. Adding columns now risks colliding with that migration.
3. **PRO plan is self-contradictory.** `src/utils/planFeatures.ts:101-119` sets
   `remote_scan: true` with `apiAccess: false` and `API_REQUESTS_PER_MONTH: 0`; since
   the envelope keys off `apiAccess` (`src/lib/auth/capabilities.ts:65`), a PRO
   subscriber gets `planActive: false` and a permanent 429.
4. **No body-size limit exists anywhere.** `next.config.ts` and `vercel.json` define
   none. An upload route is the first place a limit becomes mandatory.

## 8. Out of scope

Repository clone by URL, Git provider OAuth, SSH auth, webhooks: post-v1. They carry
credential storage, SSRF, submodule and LFS surface that is not needed yet.

## 9. Open questions

- Should the uploaded archive be stored in Supabase Storage, or handed to the worker
  through the job row? The row must not carry it; the storage choice is undecided.
- Quota unit: one repository scan is materially more expensive than one pulse. The
  existing `checkScanQuota` (10 free / 999999 paid, `usage-meter.ts:35-40`) does not
  express that.
- Whether Audit should be able to request a synchronous fast path for small
  repositories, or whether everything is always a job.
