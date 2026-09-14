// ─────────────────────────────────────────────────────────────────────────────
// auth-tester.ts — Authorization Replay Engine (Day 4)
//
// Replays a captured GraphQL request under three test strategies:
//
//   NO_AUTH       — strip Authorization header AND Cookie header entirely
//   STRIP_COOKIES — strip only Cookie header (token may live in header only)
//   MUTATE_ID     — swap every ID-pattern variable value ±1 (BOLA/IDOR probe)
//
// Each run produces an AuthTestResult with verdict + ResponseDiff evidence.
//
// Important: fetch() from the background service worker still obeys browser
// CORS rules.  If the server doesn't allow the extension origin, we receive an
// opaque/blocked response — handled as INCONCLUSIVE.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  CapturedRequest,
  AuthTestType,
  AuthVerdict,
  AuthTestResult,
  GraphQLRequestBody,
  GraphQLResponseBody,
  ResponseDiff,
} from '../types/graphql';
import { compareResponses, isVulnerable } from './response-comparator';

// ── Patterns ──────────────────────────────────────────────────────────────────

const ID_VAR_RE = /^(id|.*Id|.*_id|uuid|guid|key|pk|nodeId)$/i;

const AUTH_HEADERS = new Set([
  'authorization',
  'x-auth-token',
  'x-access-token',
  'x-api-key',
  'bearer',
  'token',
]);

// ── Helpers ───────────────────────────────────────────────────────────────────

function _stripAuthHeaders(
  headers: Record<string, string>,
  stripCookies: boolean,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lower = k.toLowerCase();
    if (AUTH_HEADERS.has(lower)) continue;
    if (stripCookies && lower === 'cookie') continue;
    result[k] = v;
  }
  return result;
}

/** Mutates every ID variable value by ±1 (tries to trigger BOLA). */
function _mutateIdVariables(
  variables: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!variables) return {};
  const mutated: Record<string, unknown> = { ...variables };
  for (const [k, v] of Object.entries(variables)) {
    if (!ID_VAR_RE.test(k)) continue;
    if (typeof v === 'number') {
      mutated[k] = v + 1;
    } else if (typeof v === 'string') {
      // Numeric string → increment
      const n = parseInt(v, 10);
      if (!isNaN(n)) {
        mutated[k] = String(n + 1);
      } else {
        // UUID-style: flip the last hex char
        mutated[k] = v.slice(0, -1) + ((parseInt(v.slice(-1), 16) + 1) % 16).toString(16);
      }
    }
  }
  return mutated;
}

/** Extracts the first response body as an object (handles batch arrays too). */
function _extractData(body: unknown): unknown {
  if (Array.isArray(body)) return (body[0] as GraphQLResponseBody)?.data ?? null;
  return (body as GraphQLResponseBody)?.data ?? null;
}

/** Builds the fetch headers for the replay. */
function _buildHeaders(
  original: Record<string, string>,
  testType:  AuthTestType,
): Record<string, string> {
  switch (testType) {
    case 'NO_AUTH':
      return _stripAuthHeaders(original, true);
    case 'STRIP_COOKIES':
      return _stripAuthHeaders(original, true); // strip cookies only
    case 'MUTATE_ID':
      // Keep all headers unchanged — we only mutate the body
      return { ...original };
  }
}

/** Builds the request body JSON string for the replay. */
function _buildBody(
  original: CapturedRequest['body'],
  testType:  AuthTestType,
): string {
  if (testType !== 'MUTATE_ID') {
    return JSON.stringify(original);
  }

  // Mutate ID variables in every operation
  const mutate = (op: GraphQLRequestBody): GraphQLRequestBody => ({
    ...op,
    variables: _mutateIdVariables(op.variables),
  });

  if (Array.isArray(original)) {
    return JSON.stringify(original.map(mutate));
  }
  return JSON.stringify(mutate(original));
}

/** Attempts to fetch + parse the replayed request. Returns null on network failure. */
async function _replay(
  request:  CapturedRequest,
  testType: AuthTestType,
): Promise<{ status: number; data: unknown; durationMs: number } | { error: string }> {
  const headers = _buildHeaders(request.requestHeaders, testType);
  const body    = _buildBody(request.body, testType);

  // Always set Content-Type — required for JSON GraphQL requests
  headers['Content-Type'] = 'application/json';

  const start = Date.now();
  try {
    const res = await fetch(request.url, {
      method:  request.method ?? 'POST',
      headers,
      body,
    });

    const durationMs = Date.now() - start;

    if (!res.ok && res.status !== 200) {
      return { status: res.status, data: null, durationMs };
    }

    let parsed: unknown = null;
    try {
      parsed = await res.json();
    } catch {
      // Non-JSON body — treat as empty data
    }

    return { status: res.status, data: parsed, durationMs };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/** Derives the AuthVerdict from a diff and replayed HTTP status. */
function _deriveVerdict(
  diff:           ResponseDiff,
  replayedStatus: number,
  testType:       AuthTestType,
): { verdict: AuthVerdict; evidence: string } {
  // HTTP 401/403 = server rejected → PROTECTED
  if (replayedStatus === 401 || replayedStatus === 403) {
    return {
      verdict:  'PROTECTED',
      evidence: `Server returned HTTP ${replayedStatus} — authorization enforced at transport layer.`,
    };
  }

  // No data leaked → check if everything was null
  if (diff.leakedFields.length === 0) {
    return {
      verdict:  'PROTECTED',
      evidence: `Replayed response contained no meaningful data (all null/empty). Server appears to enforce authorization.`,
    };
  }

  if (isVulnerable(diff)) {
    const fieldSample = diff.leakedFields.slice(0, 5).join(', ');
    const testLabel   = testType === 'NO_AUTH'       ? 'without auth headers'
                      : testType === 'STRIP_COOKIES' ? 'with cookies stripped'
                      : 'with mutated ID variables';

    return {
      verdict:  'VULNERABLE',
      evidence: `Server returned data ${testLabel}. Leaked fields: ${fieldSample}${diff.leakedFields.length > 5 ? ` (+${diff.leakedFields.length - 5} more)` : ''}.`,
    };
  }

  return {
    verdict:  'INCONCLUSIVE',
    evidence: `Response received but could not determine leak status. Diff entries: ${diff.entries.length}, leaked: ${diff.leakedFields.length}.`,
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Runs an authorization test against a captured request.
 *
 * @param request  The original captured request (must have a response to compare against).
 * @param testType Which auth-stripping strategy to apply.
 * @returns        A fully populated AuthTestResult.
 */
export async function runAuthTest(
  request:  CapturedRequest,
  testType: AuthTestType,
): Promise<AuthTestResult> {
  const id        = crypto.randomUUID();
  const testedAt  = Date.now();
  const origData  = _extractData(request.response?.body ?? null);

  // ── Perform the replay ──────────────────────────────────────────────────────
  const replayResult = await _replay(request, testType);

  // ── Handle network/CORS errors ──────────────────────────────────────────────
  if ('error' in replayResult) {
    const emptyDiff: ResponseDiff = { entries: [], leakedFields: [], fullyIdentical: true };
    return {
      id,
      requestId:          request.id,
      testType,
      testedAt,
      verdict:            'INCONCLUSIVE',
      diff:               emptyDiff,
      replayedStatus:     0,
      replayedDurationMs: 0,
      evidence: `Network error during replay (possible CORS block): ${replayResult.error}`,
    };
  }

  // ── Compare original vs. replayed ──────────────────────────────────────────
  const replayedData = _extractData(replayResult.data);
  const diff         = compareResponses(origData, replayedData);

  const { verdict, evidence } = _deriveVerdict(diff, replayResult.status, testType);

  return {
    id,
    requestId:          request.id,
    testType,
    testedAt,
    verdict,
    diff,
    replayedStatus:     replayResult.status,
    replayedDurationMs: replayResult.durationMs,
    evidence,
  };
}
