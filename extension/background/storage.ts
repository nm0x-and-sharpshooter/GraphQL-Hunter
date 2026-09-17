// ─────────────────────────────────────────────────────────────────────────────
// storage.ts — Persistent storage layer (browser.storage.local)
//
// All captured requests are persisted here so they survive popup open/close.
// Hard cap at MAX_STORED_REQUESTS to avoid blowing the 5 MB storage quota.
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import type { CapturedRequest, HunterStats, SchemaModel, AuthTestResult, Finding, FindingsStore } from '../types/graphql';
import { emptySchemaModel } from '../analysis/schema-builder';
import { severityScore, generateCurl } from '../analysis/evidence-utils';

const STORAGE_KEY          = 'gql_hunter_requests';
const SCHEMA_STORAGE_KEY   = 'gql_hunter_schema';
const FINDINGS_STORAGE_KEY = 'gql_hunter_findings';
const MAX_STORED           = 500;

// ── Read ──────────────────────────────────────────────────────────────────────

export async function getRequests(): Promise<CapturedRequest[]> {
  const result = await browser.storage.local.get(STORAGE_KEY);
  return (result[STORAGE_KEY] as CapturedRequest[] | undefined) ?? [];
}

// ── Write ─────────────────────────────────────────────────────────────────────

function getQuerySignature(body: CapturedRequest['body']): string {
  const primary = Array.isArray(body) ? body[0] : body;
  return (primary?.query ?? '').replace(/\s+/g, ' ').trim();
}

export async function saveRequest(req: CapturedRequest): Promise<void> {
  const existing = await getRequests();

  const reqQuery = getQuerySignature(req.body);
  const duplicateIndex = existing.findIndex((item) => {
    if (item.url !== req.url || item.method !== req.method) return false;
    if (Math.abs(item.timestamp - req.timestamp) > 2500) return false;
    return getQuerySignature(item.body) === reqQuery;
  });

  if (duplicateIndex !== -1) {
    const existingReq = existing[duplicateIndex];
    // If existing had no response and incoming has response, upgrade existing
    if (!existingReq.response && req.response) {
      existing[duplicateIndex] = {
        ...existingReq,
        response: req.response,
        requestHeaders:
          Object.keys(req.requestHeaders).length > 0
            ? req.requestHeaders
            : existingReq.requestHeaders,
        analysis: req.analysis ?? existingReq.analysis,
      };
      await browser.storage.local.set({ [STORAGE_KEY]: existing });
      return;
    }
    // Already recorded (with response or within deduplication window)
    return;
  }

  // Prepend newest first; trim to MAX_STORED
  const updated = [req, ...existing].slice(0, MAX_STORED);
  await browser.storage.local.set({ [STORAGE_KEY]: updated });
}

// ── Delete ────────────────────────────────────────────────────────────────────

export async function clearRequests(): Promise<void> {
  await browser.storage.local.remove(STORAGE_KEY);
}

// ── Schema persistence (Day 3) ────────────────────────────────────────────────

export async function getSchema(): Promise<SchemaModel> {
  const result = await browser.storage.local.get(SCHEMA_STORAGE_KEY);
  return (result[SCHEMA_STORAGE_KEY] as SchemaModel | undefined) ?? emptySchemaModel();
}

export async function updateSchema(model: SchemaModel): Promise<void> {
  await browser.storage.local.set({ [SCHEMA_STORAGE_KEY]: model });
}

export async function clearSchema(): Promise<void> {
  await browser.storage.local.remove(SCHEMA_STORAGE_KEY);
}

// ── Auth-test persistence (Day 4) ───────────────────────────────────────────

/**
 * Appends an AuthTestResult to the matching CapturedRequest record in storage.
 * If no matching request is found, silently does nothing (request may have
 * been cleared between test trigger and completion).
 */
export async function saveAuthTestResult(
  requestId: string,
  result:    AuthTestResult,
): Promise<void> {
  const requests = await getRequests();
  const idx      = requests.findIndex(r => r.id === requestId);
  if (idx === -1) return;

  const req = requests[idx];
  req.authTests = [...(req.authTests ?? []), result];
  await browser.storage.local.set({ [STORAGE_KEY]: requests });
}

/**
 * Returns all auth-test results for a given request ID, ordered oldest-first.
 */
export async function getAuthTestResults(requestId: string): Promise<AuthTestResult[]> {
  const requests = await getRequests();
  const req      = requests.find(r => r.id === requestId);
  return req?.authTests ?? [];
}

// ── Findings persistence (Day 5) ────────────────────────────────────────

async function _getStore(): Promise<FindingsStore> {
  const result = await browser.storage.local.get(FINDINGS_STORAGE_KEY);
  return (result[FINDINGS_STORAGE_KEY] as FindingsStore | undefined)
    ?? { findings: [], lastUpdated: 0 };
}

/**
 * Creates a Finding from an AuthTestResult and persists it.
 * Deduplicates by (requestId, testType) — if a finding for the same pair
 * already exists, it is replaced with the latest result.
 *
 * @param result      The auth-test result produced by runAuthTest().
 * @param requestUrl  Full endpoint URL of the originating request.
 * @param opName      Primary operation name (or 'anonymous').
 * @param curl        Pre-generated curl command for reproduction.
 */
export async function saveFinding(
  result:     AuthTestResult,
  requestUrl: string,
  opName:     string,
  curl:       string,
): Promise<void> {
  const store = await _getStore();

  const finding: Finding = {
    id:            result.id,
    requestId:     result.requestId,
    requestUrl,
    operationName: opName,
    result,
    severityScore: severityScore(result.verdict),
    note:          '',
    curl,
  };

  // Deduplicate: replace existing (requestId, testType) pair
  const idx = store.findings.findIndex(
    f => f.requestId === result.requestId && f.result.testType === result.testType,
  );

  if (idx !== -1) {
    // Preserve existing analyst note when replacing
    finding.note = store.findings[idx].note;
    store.findings[idx] = finding;
  } else {
    store.findings.unshift(finding);
  }

  store.lastUpdated = Date.now();
  await browser.storage.local.set({ [FINDINGS_STORAGE_KEY]: store });
}

/**
 * Returns all findings, sorted by severityScore desc, then testedAt desc.
 */
export async function getFindings(): Promise<Finding[]> {
  const store = await _getStore();
  return store.findings.sort((a, b) => {
    if (b.severityScore !== a.severityScore) return b.severityScore - a.severityScore;
    return b.result.testedAt - a.result.testedAt;
  });
}

/**
 * Patches the analyst note on an existing finding.
 * Silently no-ops if the finding ID is not found.
 */
export async function updateFindingNote(
  findingId: string,
  note:      string,
): Promise<void> {
  const store = await _getStore();
  const idx   = store.findings.findIndex(f => f.id === findingId);
  if (idx === -1) return;
  store.findings[idx].note = note;
  store.lastUpdated = Date.now();
  await browser.storage.local.set({ [FINDINGS_STORAGE_KEY]: store });
}

/**
 * Removes all persisted findings.
 */
export async function clearFindings(): Promise<void> {
  await browser.storage.local.remove(FINDINGS_STORAGE_KEY);
}

// ── Aggregate stats ───────────────────────────────────────────────────────────

export async function getStats(): Promise<HunterStats> {
  const [requests, findings] = await Promise.all([getRequests(), getFindings()]);

  let queries = 0;
  let mutations = 0;
  let batches = 0;
  let riskCount = 0;
  const seen = new Set<string>();

  for (const req of requests) {
    // Normalise to array (handles single + batch)
    const bodies = Array.isArray(req.body) ? req.body : [req.body];

    if (req.isBatch) batches++;

    for (const b of bodies) {
      const firstToken = b.query.trim().slice(0, 20).toLowerCase();
      if (firstToken.startsWith('mutation')) mutations++;
      else queries++;
    }

    if (
      req.analysis &&
      (req.analysis.overallRisk === 'CRITICAL' ||
        req.analysis.overallRisk === 'HIGH' ||
        req.analysis.overallRisk === 'MEDIUM')
    ) {
      riskCount++;
    }

    // Deduplicate by origin + pathname
    try {
      const u = new URL(req.url);
      seen.add(u.origin + u.pathname);
    } catch {
      seen.add(req.url);
    }
  }

  // Day 5: finding verdict counts
  const vulnerableCount   = findings.filter(f => f.result.verdict === 'VULNERABLE').length;
  const inconclusiveCount = findings.filter(f => f.result.verdict === 'INCONCLUSIVE').length;
  const protectedCount    = findings.filter(f => f.result.verdict === 'PROTECTED').length;

  return {
    totalRequests:    requests.length,
    endpoints:        [...seen],
    batchCount:       batches,
    mutationCount:    mutations,
    queryCount:       queries,
    riskCount,
    vulnerableCount,
    inconclusiveCount,
    protectedCount,
  };
}
