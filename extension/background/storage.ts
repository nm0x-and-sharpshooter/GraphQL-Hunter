// ─────────────────────────────────────────────────────────────────────────────
// storage.ts — Persistent storage layer (browser.storage.local)
//
// All captured requests are persisted here so they survive popup open/close.
// Hard cap at MAX_STORED_REQUESTS to avoid blowing the 5 MB storage quota.
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import type { CapturedRequest, HunterStats, SchemaModel } from '../types/graphql';
import { emptySchemaModel } from '../analysis/schema-builder';

const STORAGE_KEY        = 'gql_hunter_requests';
const SCHEMA_STORAGE_KEY = 'gql_hunter_schema';
const MAX_STORED         = 500;

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

// ── Aggregate stats ───────────────────────────────────────────────────────────

export async function getStats(): Promise<HunterStats> {
  const requests = await getRequests();

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

  return {
    totalRequests: requests.length,
    endpoints: [...seen],
    batchCount: batches,
    mutationCount: mutations,
    queryCount: queries,
    riskCount,
  };
}
