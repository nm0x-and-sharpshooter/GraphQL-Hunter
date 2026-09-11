// ─────────────────────────────────────────────────────────────────────────────
// request-observer.ts — GraphQL Traffic Interception Engine
//
// Strategy:
//  1. browser.webRequest.onBeforeRequest  → capture POST request body
//     + call filterResponseData()         → stream-capture the response body
//  2. browser.webRequest.onSendHeaders    → capture outbound headers
//  3. browser.webRequest.onHeadersReceived → capture response status + headers
//  4. browser.webRequest.onCompleted /
//     browser.webRequest.onErrorOccurred  → GC the pendingRequests map
//
// Firefox-specific note:
//   filterResponseData() is a Firefox-only API. It creates a StreamFilter that
//   lets us read (and passthrough) the raw response bytes without blocking the
//   page. We must pass "blocking" in onBeforeRequest's extraInfoSpec for this
//   to work.
//
// Detection heuristics — a request is treated as GraphQL when:
//   (a) The POST body deserialises to JSON with a "query" string field, OR
//   (b) The URL matches a known GraphQL path pattern AND body is JSON
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import type {
  CapturedRequest,
  CapturedResponse,
  GraphQLRequestBody,
  GraphQLResponseBody,
} from '../types/graphql';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Firefox StreamFilter — not fully typed in webextension-polyfill. */
interface StreamFilter {
  ondata:   ((event: { data: ArrayBuffer }) => void) | null;
  onstop:   (() => void) | null;
  onerror:  (() => void) | null;
  write(data: ArrayBuffer | Uint8Array): void;
  disconnect(): void;
  close(): void;
}

interface FirefoxWebRequest {
  filterResponseData(requestId: string): StreamFilter;
}

interface PendingEntry {
  request:   CapturedRequest;
  startTime: number;
  /** Accumulated response headers (filled in onHeadersReceived). */
  responseStatus?:       number;
  responseStatusText?:   string;
  responseHeaders?:      Record<string, string>;
}

// ── State ─────────────────────────────────────────────────────────────────────

/** In-flight requests waiting for their response. */
const pending = new Map<string, PendingEntry>();

/** Callback invoked when a full request+response pair is ready. */
let captureCallback: ((req: CapturedRequest) => void) | null = null;

// ── Public API ────────────────────────────────────────────────────────────────

export function onRequestCaptured(cb: (req: CapturedRequest) => void): void {
  captureCallback = cb;
}

export function startObserving(): void {
  _hookBeforeRequest();
  _hookSendHeaders();
  _hookHeadersReceived();
  _hookCleanup();
  console.log('[GraphQL Hunter] Request observer active.');
}

// ── GraphQL detection helpers ─────────────────────────────────────────────────

/** URL patterns strongly associated with GraphQL endpoints. */
const GQL_URL_RE = /\/(graphql|gql|api\/graphql|api\/gql|query)(\/|$|\?)/i;

function isGraphQLUrl(url: string): boolean {
  return GQL_URL_RE.test(url);
}

/**
 * Returns true if `obj` looks like a GraphQL request body:
 *   { query: "..." [, variables, operationName, extensions] }
 */
function isGraphQLBody(obj: unknown): obj is GraphQLRequestBody {
  if (typeof obj !== 'object' || obj === null) return false;
  const o = obj as Record<string, unknown>;
  return typeof o['query'] === 'string' && o['query'].trim().length > 0;
}

/**
 * Decodes the raw requestBody bytes from the webRequest API into a string.
 * Returns null if no bytes were present.
 */
function decodeRequestBodyBytes(
  details: browser.WebRequest.OnBeforeRequestDetailsType,
): string | null {
  const rawParts = details.requestBody?.raw;
  if (!rawParts || rawParts.length === 0) return null;

  const chunks = rawParts
    .filter((p): p is { bytes: ArrayBuffer } => p.bytes != null)
    .map(p => new Uint8Array(p.bytes as ArrayBuffer));

  if (chunks.length === 0) return null;

  const totalLen = chunks.reduce((n, c) => n + c.length, 0);
  const merged = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }

  return new TextDecoder('utf-8').decode(merged);
}

/**
 * Parses a raw body string and returns:
 *   - A single GraphQLRequestBody (single operation)
 *   - An array of GraphQLRequestBody (batched request)
 *   - null if the body is not GraphQL
 */
function parseGraphQLBody(
  raw: string,
): GraphQLRequestBody | GraphQLRequestBody[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (isGraphQLBody(parsed)) return parsed;

  if (Array.isArray(parsed) && parsed.length > 0 && parsed.every(isGraphQLBody)) {
    return parsed as GraphQLRequestBody[];
  }

  return null;
}

// ── Listener implementations ──────────────────────────────────────────────────

/**
 * Hook 1 — onBeforeRequest (blocking + requestBody)
 *
 * Runs synchronously before the request is sent.
 * - Decodes and validates the request body as GraphQL
 * - Registers the request in `pending`
 * - Attaches a StreamFilter to capture the response body passively
 */
function _hookBeforeRequest(): void {
  browser.webRequest.onBeforeRequest.addListener(
    (details) => {
      // Only care about POST requests
      if (details.method !== 'POST') return {};

      // Decode the raw body bytes
      const rawBody = decodeRequestBodyBytes(details);
      if (!rawBody) {
        // No body bytes — might be a Fetch with body in content-script context;
        // URL-based detection as a fallback (we'll get it from content script later)
        return {};
      }

      // Parse body — if it's not GraphQL, bail
      const parsedBody = parseGraphQLBody(rawBody);
      if (!parsedBody) {
        // Body isn't GraphQL. Check URL as secondary signal.
        if (!isGraphQLUrl(details.url)) return {};
        // URL matches but body isn't parseable as GQL — skip.
        return {};
      }

      // ── Register the pending request ──
      const capturedRequest: CapturedRequest = {
        id:             crypto.randomUUID(),
        requestId:      details.requestId,
        url:            details.url,
        tabId:          details.tabId,
        timestamp:      Date.now(),
        method:         details.method,
        requestHeaders: {},          // filled in _hookSendHeaders
        body:           parsedBody,
        isBatch:        Array.isArray(parsedBody),
        response:       undefined,
      };

      pending.set(details.requestId, {
        request:   capturedRequest,
        startTime: Date.now(),
      });

      // ── Attach StreamFilter for response body capture ──
      try {
        const ff = browser.webRequest as unknown as FirefoxWebRequest;
        const filter = ff.filterResponseData(details.requestId);
        _attachStreamFilter(filter, details.requestId);
      } catch (err) {
        console.warn('[GraphQL Hunter] filterResponseData unavailable:', err);
      }

      return {}; // Don't block the request — we're just observing
    },
    { urls: ['<all_urls>'] },
    ['requestBody', 'blocking'],
  );
}

/**
 * Hook 2 — onSendHeaders
 *
 * Fires just before headers are sent. We use this to record outbound headers
 * (Authorization, Cookie, X-Auth-Token, etc.) for evidence later.
 */
function _hookSendHeaders(): void {
  browser.webRequest.onSendHeaders.addListener(
    (details) => {
      const entry = pending.get(details.requestId);
      if (!entry) return;

      const headers: Record<string, string> = {};
      for (const h of details.requestHeaders ?? []) {
        if (h.name && h.value) {
          headers[h.name.toLowerCase()] = h.value;
        }
      }
      entry.request.requestHeaders = headers;
    },
    { urls: ['<all_urls>'] },
    ['requestHeaders'],
  );
}

/**
 * Hook 3 — onHeadersReceived
 *
 * Fires when the server responds with headers. We capture the HTTP status and
 * response headers here; the body arrives later through the StreamFilter.
 */
function _hookHeadersReceived(): void {
  browser.webRequest.onHeadersReceived.addListener(
    (details) => {
      const entry = pending.get(details.requestId);
      if (!entry) return;

      const headers: Record<string, string> = {};
      for (const h of details.responseHeaders ?? []) {
        if (h.name && h.value) {
          headers[h.name.toLowerCase()] = h.value;
        }
      }

      entry.responseStatus     = details.statusCode;
      entry.responseStatusText = details.statusLine ?? '';
      entry.responseHeaders    = headers;
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders'],
  );
}

/**
 * Hook 4 — onCompleted + onErrorOccurred
 *
 * Garbage-collect any pending entries that somehow never emitted a response
 * (e.g. the page was closed before the filter onstop fired).
 */
function _hookCleanup(): void {
  const cleanup = (details: { requestId: string }) => {
    // Only remove if the StreamFilter already finalised the entry; otherwise
    // we'd race with _attachStreamFilter's onstop handler.
    // We give the filter 5 s to flush before force-removing.
    setTimeout(() => {
      if (pending.has(details.requestId)) {
        console.debug('[GraphQL Hunter] GC pending entry:', details.requestId);
        pending.delete(details.requestId);
      }
    }, 5000);
  };

  browser.webRequest.onCompleted.addListener(cleanup,     { urls: ['<all_urls>'] });
  browser.webRequest.onErrorOccurred.addListener(cleanup, { urls: ['<all_urls>'] });
}

// ── StreamFilter helpers ──────────────────────────────────────────────────────

/**
 * Attaches event handlers to a Firefox StreamFilter.
 *
 * Data is passed through unchanged (we never modify traffic).
 * When onstop fires, we decode the accumulated bytes, parse the JSON,
 * complete the pending entry, and fire captureCallback.
 */
function _attachStreamFilter(filter: StreamFilter, requestId: string): void {
  const chunks: ArrayBuffer[] = [];

  filter.ondata = (event) => {
    chunks.push(event.data);
    filter.write(event.data); // Pass through — never block the page
  };

  filter.onstop = () => {
    const entry = pending.get(requestId);

    if (!entry) {
      filter.disconnect();
      return;
    }

    // Merge accumulated chunks
    const totalLen = chunks.reduce((n, c) => n + c.byteLength, 0);
    const merged = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(new Uint8Array(chunk), offset);
      offset += chunk.byteLength;
    }

    const responseText = new TextDecoder('utf-8').decode(merged);
    const endTime = Date.now();

    let parsedBody: GraphQLResponseBody | GraphQLResponseBody[];
    try {
      parsedBody = JSON.parse(responseText) as GraphQLResponseBody | GraphQLResponseBody[];
    } catch {
      // Response isn't JSON — not a standard GraphQL response; discard.
      pending.delete(requestId);
      filter.disconnect();
      return;
    }

    // Build the complete CapturedResponse
    const capturedResponse: CapturedResponse = {
      status:          entry.responseStatus      ?? 0,
      statusText:      entry.responseStatusText  ?? '',
      responseHeaders: entry.responseHeaders     ?? {},
      body:            parsedBody,
      timestamp:       endTime,
      durationMs:      endTime - entry.startTime,
    };

    entry.request.response = capturedResponse;

    // Remove from pending and fire callback
    pending.delete(requestId);
    captureCallback?.(entry.request);

    filter.disconnect();
  };

  filter.onerror = () => {
    pending.delete(requestId);
    filter.disconnect();
  };
}
