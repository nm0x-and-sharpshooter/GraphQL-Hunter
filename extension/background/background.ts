// ─────────────────────────────────────────────────────────────────────────────
// background.ts — Extension entry point (background / service worker)
//
// Responsibilities:
//   1. Start the request observer (network interception via webRequest)
//   2. Start the message router (popup ↔ background communication)
//   3. Handle page hook captures (fetch/XHR interception from page world)
//   4. Run query analysis engine & heuristic risk scoring on all captured traffic
//   5. Persist to storage and broadcast live updates to popup
// ─────────────────────────────────────────────────────────────────────────────

import { startObserving, onRequestCaptured } from './request-observer';
import { startMessageRouter, broadcast, onPageHookCaptured } from './message-router';
import { saveRequest, getSchema, updateSchema } from './storage';
import { analyzeRequest } from '../analysis/query-analyzer';
import { mergeRequestIntoSchema } from '../analysis/schema-builder';
import type { CapturedRequest, GraphQLRequestBody } from '../types/graphql';
import type { PageHookPayload } from '../types/messages';

console.log('[GraphQL Hunter] Background script initialising…');

/**
 * Common handler to process, score, persist, and broadcast any captured GraphQL traffic.
 */
async function processCapturedRequest(request: CapturedRequest, source: string): Promise<void> {
  // Day 2: Run AST-based query analyzer and heuristic risk scorer
  request.analysis = analyzeRequest(request);

  // Day 3: Incrementally update the persisted schema model
  try {
    const schema = await getSchema();
    mergeRequestIntoSchema(schema, request);
    await updateSchema(schema);
  } catch (err) {
    console.warn('[GraphQL Hunter] Schema update failed:', err);
  }

  const ops = Array.isArray(request.body) ? request.body : [request.body];
  const opNames = ops
    .map(o => o.operationName ?? _inferName(o.query))
    .filter(Boolean)
    .join(', ');

  console.log(
    `[GraphQL Hunter] [${source}] Captured: ${request.url} | ops: [${opNames || 'anonymous'}]`,
    `| status: ${request.response?.status ?? 'pending'}`,
    `| risk: ${request.analysis.overallRisk}`,
    `| ${request.isBatch ? 'BATCH' : 'single'}`,
  );

  // Persist to storage (with deduplication)
  await saveRequest(request);

  // Live-push to popup (if open)
  await broadcast({ type: 'GRAPHQL_REQUEST_CAPTURED', payload: request });
}

// ── Wire up the capture pipelines ─────────────────────────────────────────────

// 1. webRequest API pipeline
onRequestCaptured(async (request) => {
  await processCapturedRequest(request, 'webRequest');
});

// 2. Page-world fetch/XHR hook pipeline
onPageHookCaptured(async (payload: PageHookPayload, tabId: number) => {
  const isBatch = Array.isArray(payload.body);
  const captured: CapturedRequest = {
    id: crypto.randomUUID(),
    requestId: `hook-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    url: payload.url,
    tabId,
    timestamp: Date.now(),
    method: payload.method,
    requestHeaders: {},
    body: payload.body,
    isBatch,
  };

  await processCapturedRequest(captured, `hook:${payload.source}`);
});

// ── Boot ─────────────────────────────────────────────────────────────────────

startObserving();
startMessageRouter();

console.log('[GraphQL Hunter] Background script ready. Hunting GraphQL traffic…');

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Quick regex-based operation name extraction (no AST needed for quick fallback). */
function _inferName(query: string): string {
  const m = query.match(/(?:query|mutation|subscription)\s+(\w+)/i);
  return m?.[1] ?? '';
}
