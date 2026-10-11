// ─────────────────────────────────────────────────────────────────────────────
// injection-scanner.ts — Day 7: Advanced Injection & Logic Flaw Scanner
//
// Three attack surfaces:
//   1. Directive Bypass   — AST manipulation injecting @skip(if: false) and
//                           @include(if: true) to test resolver auth guard bypasses.
//   2. Variable Injection — SQLi/NoSQLi/SSTI probes via captured query variables,
//                           with error pattern matching for database leak detection.
//   3. Transport/CSRF     — HTTP GET query delivery and simple Content-Type
//                           preflight bypass (form-urlencoded, text/plain).
//
// All functions return AttackPayload[] and FuzzHit[] that integrate directly
// with the existing attack-engine.ts dispatcher and AttackJob model.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  GraphQLRequestBody,
  GraphQLResponseBody,
  AttackPayload,
  FuzzHit,
} from '../types/graphql';

import {
  SQLI_PROBES,
  NOSQLI_PROBES,
  SSTI_PROBES,
  INJECTABLE_VARIABLE_NAMES,
  INJECTION_ERROR_PATTERNS,
} from './wordlist';

// ── Shared Helpers ────────────────────────────────────────────────────────────

/** Extract error messages from a GraphQL response body (single or batched). */
function _extractErrors(body: GraphQLResponseBody | GraphQLResponseBody[]): string[] {
  const responses = Array.isArray(body) ? body : [body];
  return responses.flatMap(r => (r.errors ?? []).map(e => e.message));
}

/** Check whether a response body has any non-null data. */
function _hasData(body: GraphQLResponseBody | GraphQLResponseBody[]): boolean {
  const responses = Array.isArray(body) ? body : [body];
  return responses.some(r => r.data != null && Object.keys(r.data).length > 0);
}

/** POST dispatcher — sends a GraphQL body as JSON via POST. */
async function _dispatchPost(
  url: string,
  headers: Record<string, string>,
  body: GraphQLRequestBody | GraphQLRequestBody[],
): Promise<{ status: number; durationMs: number; body: GraphQLResponseBody | GraphQLResponseBody[]; raw: string }> {
  const start = Date.now();
  try {
    const resp = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body:    JSON.stringify(body),
    });
    const raw = await resp.text();
    let parsed: GraphQLResponseBody | GraphQLResponseBody[];
    try   { parsed = JSON.parse(raw); }
    catch { parsed = { errors: [{ message: raw }] }; }
    return { status: resp.status, durationMs: Date.now() - start, body: parsed, raw };
  } catch (err) {
    return {
      status:     0,
      durationMs: Date.now() - start,
      body:       { errors: [{ message: String(err) }] },
      raw:        '',
    };
  }
}

/** GET dispatcher — sends query via URL query parameters. */
async function _dispatchGet(
  url: string,
  headers: Record<string, string>,
  body: GraphQLRequestBody,
): Promise<{ status: number; durationMs: number; body: GraphQLResponseBody | GraphQLResponseBody[]; raw: string }> {
  const start = Date.now();
  try {
    const u = new URL(url);
    u.searchParams.set('query', body.query);
    if (body.operationName) u.searchParams.set('operationName', body.operationName);
    if (body.variables && Object.keys(body.variables).length > 0) {
      u.searchParams.set('variables', JSON.stringify(body.variables));
    }

    // Strip Content-Type (GET doesn't need it) but keep other headers
    const getHeaders = { ...headers };
    delete getHeaders['Content-Type'];
    delete getHeaders['content-type'];

    const resp = await fetch(u.toString(), { method: 'GET', headers: getHeaders });
    const raw = await resp.text();
    let parsed: GraphQLResponseBody | GraphQLResponseBody[];
    try   { parsed = JSON.parse(raw); }
    catch { parsed = { errors: [{ message: raw }] }; }
    return { status: resp.status, durationMs: Date.now() - start, body: parsed, raw };
  } catch (err) {
    return {
      status:     0,
      durationMs: Date.now() - start,
      body:       { errors: [{ message: String(err) }] },
      raw:        '',
    };
  }
}

/** POST dispatcher with a specific Content-Type override (for CSRF testing). */
async function _dispatchWithContentType(
  url: string,
  headers: Record<string, string>,
  body: GraphQLRequestBody,
  contentType: string,
): Promise<{ status: number; durationMs: number; body: GraphQLResponseBody | GraphQLResponseBody[]; raw: string }> {
  const start = Date.now();
  try {
    let encodedBody: string;

    if (contentType === 'application/x-www-form-urlencoded') {
      const params = new URLSearchParams();
      params.set('query', body.query);
      if (body.operationName) params.set('operationName', body.operationName);
      if (body.variables && Object.keys(body.variables).length > 0) {
        params.set('variables', JSON.stringify(body.variables));
      }
      encodedBody = params.toString();
    } else {
      // text/plain — send raw JSON text but with text/plain Content-Type
      encodedBody = JSON.stringify(body);
    }

    const sendHeaders = { ...headers, 'Content-Type': contentType };

    const resp = await fetch(url, {
      method:  'POST',
      headers: sendHeaders,
      body:    encodedBody,
    });
    const raw = await resp.text();
    let parsed: GraphQLResponseBody | GraphQLResponseBody[];
    try   { parsed = JSON.parse(raw); }
    catch { parsed = { errors: [{ message: raw }] }; }
    return { status: resp.status, durationMs: Date.now() - start, body: parsed, raw };
  } catch (err) {
    return {
      status:     0,
      durationMs: Date.now() - start,
      body:       { errors: [{ message: String(err) }] },
      raw:        '',
    };
  }
}

// ── Compiled error patterns (cached) ──────────────────────────────────────────

const COMPILED_ERROR_PATTERNS = INJECTION_ERROR_PATTERNS.map(p => ({
  regex: new RegExp(p.pattern, 'i'),
  label: p.label,
}));

/** Checks response errors against known database/template error signatures. */
function matchInjectionPatterns(errors: string[], rawBody: string): { label: string; match: string }[] {
  const hits: { label: string; match: string }[] = [];
  const allText = [...errors, rawBody].join('\n');

  for (const { regex, label } of COMPILED_ERROR_PATTERNS) {
    const m = allText.match(regex);
    if (m) {
      hits.push({ label, match: m[0].slice(0, 200) });
    }
  }

  return hits;
}

/** Check for SSTI reflection (e.g. "49" appearing in response for 7*7). */
function checkSSTIReflection(rawBody: string): boolean {
  // 7*7 = 49 — look for the arithmetic result in the response
  return rawBody.includes('49');
}

// ═══════════════════════════════════════════════════════════════════════════════
//  1. DIRECTIVE BYPASS SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generates directive-injected variants of a captured query.
 *
 * Strategy:
 *   1. Send the original query as a baseline.
 *   2. Inject `@skip(if: false)` on root fields — forces execution while
 *      potentially bypassing server-side field-level auth checks that
 *      inspect the AST but miss directive conditions.
 *   3. Inject `@include(if: true)` — same bypass vector, different directive.
 *   4. Test `@skip(if: true)` — control baseline verifying that the directive
 *      engine correctly suppresses the field.
 *   5. Compare response data: if data appears under @skip(if: false) that was
 *      absent or errored in the baseline, flag DIRECTIVE_AUTH_BYPASS.
 */
export async function runDirectiveBypass(
  url: string,
  headers: Record<string, string>,
  primary: GraphQLRequestBody,
): Promise<{ payloads: AttackPayload[]; fuzzHits: FuzzHit[] }> {
  const payloads: AttackPayload[] = [];
  const fuzzHits: FuzzHit[]       = [];

  // Extract root field for directive injection
  const rootFieldMatch = primary.query.match(/(?:query|mutation)\s*\w*\s*(?:\([^)]*\))?\s*\{\s*(\w+)/);
  const rootField      = rootFieldMatch?.[1] ?? 'user';

  // ── Step 1: Baseline (original query) ─────────────────────────────────────
  const baselineResult = await _dispatchPost(url, headers, primary);
  const baselineHasData = _hasData(baselineResult.body);

  payloads.push({
    id:         crypto.randomUUID(),
    attackType: 'DIRECTIVE_BYPASS',
    sentBody:   primary,
    response:   { status: baselineResult.status, durationMs: baselineResult.durationMs, body: baselineResult.body, raw: baselineResult.raw },
    outcome:    baselineHasData ? 'HIT' : 'MISS',
    evidence:   `Baseline query: ${baselineHasData ? 'data returned' : 'no data'}. Status ${baselineResult.status}.`,
  });

  // ── Directive injection variants ──────────────────────────────────────────

  const directiveVariants: { directive: string; description: string; expectData: boolean }[] = [
    { directive: '@skip(if: false)',    description: 'Forces field execution (should bypass @skip-based auth)',  expectData: true  },
    { directive: '@include(if: true)',  description: 'Forces field inclusion (should bypass @include-based auth)', expectData: true  },
    { directive: '@skip(if: true)',     description: 'Control: should suppress field (no data expected)',        expectData: false },
  ];

  for (const variant of directiveVariants) {
    // Inject the directive after the root field name in the query
    const injectedQuery = primary.query.replace(
      new RegExp(`(${rootField})(\\s*(?:\\([^)]*\\))?\\s*\\{)`),
      `$1 ${variant.directive}$2`,
    );

    // If injection didn't alter the query, construct a simple one
    const effectiveQuery = injectedQuery !== primary.query
      ? injectedQuery
      : `query DirectiveProbe { ${rootField} ${variant.directive} { __typename } }`;

    const body: GraphQLRequestBody = {
      operationName: `DirectiveProbe_${variant.directive.replace(/[^a-zA-Z]/g, '')}`,
      query:         effectiveQuery,
      variables:     primary.variables ?? {},
    };

    const result = await _dispatchPost(url, headers, body);
    const errs   = _extractErrors(result.body);
    const hasData = _hasData(result.body);

    // Determine outcome
    let outcome: 'HIT' | 'MISS' | 'BLOCKED' | 'ERROR' = 'MISS';
    let evidence: string;

    const directiveRejected = errs.some(e =>
      e.toLowerCase().includes('directive') ||
      e.toLowerCase().includes('unknown') ||
      e.toLowerCase().includes('not allowed'),
    );

    if (directiveRejected) {
      outcome  = 'BLOCKED';
      evidence = `Server rejected ${variant.directive}: ${errs[0]?.slice(0, 200)}`;
    } else if (hasData && variant.expectData) {
      // @skip(if: false) or @include(if: true) returned data
      // Check if this represents a bypass (data appeared that wasn't in baseline)
      if (!baselineHasData) {
        outcome = 'HIT';
        evidence = `⚠️ BYPASS DETECTED: ${variant.directive} returned data that was absent in baseline. ${variant.description}`;
        fuzzHits.push({
          field:    rootField,
          evidence: `Directive ${variant.directive} bypassed authorization — data returned for previously blocked field "${rootField}"`,
          hitType:  'DIRECTIVE_AUTH_BYPASS',
        });
      } else {
        outcome  = 'HIT';
        evidence = `${variant.directive} accepted and returned data. ${variant.description}`;
      }
    } else if (hasData && !variant.expectData) {
      // @skip(if: true) returned data — that's suspicious (server ignores directives?)
      outcome = 'HIT';
      evidence = `⚠️ ${variant.directive} should suppress the field but data was returned. Server may not process directives correctly.`;
      fuzzHits.push({
        field:    rootField,
        evidence: `Server ignored ${variant.directive} — field "${rootField}" was not skipped`,
        hitType:  'DIRECTIVE_AUTH_BYPASS',
      });
    } else {
      outcome  = errs.length > 0 ? 'ERROR' : 'MISS';
      evidence = errs[0]?.slice(0, 200) ?? `No data returned for ${variant.directive}`;
    }

    payloads.push({
      id:         crypto.randomUUID(),
      attackType: 'DIRECTIVE_BYPASS',
      sentBody:   body,
      response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
      outcome,
      evidence,
    });
  }

  return { payloads, fuzzHits };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  2. VARIABLE INJECTION FUZZER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Injects SQLi, NoSQLi, and SSTI probes into captured query variables.
 *
 * Strategy:
 *   1. Identify injectable variables from the captured request (by name heuristic
 *      or all string/unknown-typed variables).
 *   2. For each injectable variable, send each probe payload as the value.
 *   3. Inspect response errors for known database error patterns.
 *   4. Check raw response body for SSTI reflection (49 for 7*7).
 *   5. Classify hits: CRITICAL for confirmed injection, HIGH for error leaks.
 */
export async function runVariableInjection(
  url: string,
  headers: Record<string, string>,
  primary: GraphQLRequestBody,
): Promise<{ payloads: AttackPayload[]; fuzzHits: FuzzHit[] }> {
  const payloads: AttackPayload[] = [];
  const fuzzHits: FuzzHit[]       = [];

  // Identify target variables from the captured query
  const capturedVars = primary.variables ?? {};
  const varNames     = Object.keys(capturedVars);

  // If no variables in original request, try to parse variable definitions from query
  const targetVars: string[] = varNames.length > 0
    ? varNames.filter(v => INJECTABLE_VARIABLE_NAMES.includes(v) || varNames.length <= 5)
    : _extractVariableNames(primary.query);

  if (targetVars.length === 0) {
    // Fallback: create a simple query with an injectable variable
    payloads.push({
      id:         crypto.randomUUID(),
      attackType: 'VARIABLE_INJECTION',
      sentBody:   primary,
      response:   { status: 0, durationMs: 0, body: { errors: [{ message: 'No injectable variables found' }] }, raw: '' },
      outcome:    'MISS',
      evidence:   'No injectable variables detected in the captured query.',
    });
    return { payloads, fuzzHits };
  }

  // Build all probe sets
  const allProbes: { probe: string; category: string }[] = [
    ...SQLI_PROBES.map(p   => ({ probe: p, category: 'SQLi' })),
    ...NOSQLI_PROBES.map(p => ({ probe: p, category: 'NoSQLi' })),
    ...SSTI_PROBES.map(p   => ({ probe: p, category: 'SSTI' })),
  ];

  // Limit total requests to avoid excessive traffic
  const maxProbesPerVar = 8;
  const probesToRun     = allProbes.slice(0, maxProbesPerVar);

  for (const varName of targetVars.slice(0, 3)) {  // Max 3 variables
    for (const { probe, category } of probesToRun) {
      // Clone variables and inject the probe
      const injectedVars = { ...capturedVars };

      // For NoSQLi, try to parse as JSON object; otherwise inject as string
      if (category === 'NoSQLi') {
        try {
          injectedVars[varName] = JSON.parse(probe);
        } catch {
          injectedVars[varName] = probe;
        }
      } else {
        injectedVars[varName] = probe;
      }

      const body: GraphQLRequestBody = {
        operationName: primary.operationName ?? 'InjectionProbe',
        query:         primary.query,
        variables:     injectedVars,
      };

      const result = await _dispatchPost(url, headers, body);
      const errs   = _extractErrors(result.body);

      // Check for injection error pattern matches
      const patternMatches = matchInjectionPatterns(errs, result.raw);

      // Check for SSTI reflection
      const hasReflection = category === 'SSTI' && checkSSTIReflection(result.raw);

      // Determine outcome
      let outcome: 'HIT' | 'MISS' | 'BLOCKED' | 'ERROR' = 'MISS';
      let evidence: string;

      if (patternMatches.length > 0) {
        outcome  = 'HIT';
        evidence = `🔴 ${category} injection detected in $${varName}! Backend error: [${patternMatches[0].label}] "${patternMatches[0].match}"`;
        fuzzHits.push({
          field:    `$${varName}`,
          evidence: `${category} injection: ${patternMatches[0].label} — probe: "${probe.slice(0, 60)}"`,
          hitType:  'INJECTION_ERROR_LEAK',
        });
      } else if (hasReflection) {
        outcome  = 'HIT';
        evidence = `🟡 SSTI reflection detected in $${varName}! Response contains "49" (7*7 computation result). Probe: "${probe}"`;
        fuzzHits.push({
          field:    `$${varName}`,
          evidence: `SSTI reflection: response contains computed value "49" for probe "${probe}"`,
          hitType:  'INJECTION_REFLECTION',
        });
      } else if (errs.length > 0) {
        // Server returned errors but no known pattern — might still be interesting
        const hasGenericError = errs.some(e =>
          e.toLowerCase().includes('internal') ||
          e.toLowerCase().includes('unexpected') ||
          e.toLowerCase().includes('exception'),
        );
        if (hasGenericError) {
          outcome  = 'HIT';
          evidence = `⚠️ Server threw internal/unexpected error for ${category} probe in $${varName}: "${errs[0]?.slice(0, 200)}"`;
          fuzzHits.push({
            field:    `$${varName}`,
            evidence: `Unhandled server error for ${category} probe: "${errs[0]?.slice(0, 100)}"`,
            hitType:  'INJECTION_ERROR_LEAK',
          });
        } else {
          outcome  = 'MISS';
          evidence = `${category} probe in $${varName} returned error (likely validation): "${errs[0]?.slice(0, 200)}"`;
        }
      } else {
        outcome  = 'MISS';
        evidence = `${category} probe in $${varName}: no error or reflection. Server handled input cleanly.`;
      }

      payloads.push({
        id:         crypto.randomUUID(),
        attackType: 'VARIABLE_INJECTION',
        sentBody:   body,
        response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
        outcome,
        evidence,
      });
    }
  }

  return { payloads, fuzzHits };
}

/** Extract variable names from a GraphQL query's variable definitions. */
function _extractVariableNames(query: string): string[] {
  const matches = query.matchAll(/\$(\w+)\s*:/g);
  const names: string[] = [];
  for (const m of matches) {
    if (m[1] && !names.includes(m[1])) names.push(m[1]);
  }
  // If none found in definitions, look for variable references
  if (names.length === 0) {
    const refs = query.matchAll(/\$(\w+)/g);
    for (const m of refs) {
      if (m[1] && !names.includes(m[1])) names.push(m[1]);
    }
  }
  return names;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  3. TRANSPORT & CSRF VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Tests whether the GraphQL endpoint accepts queries via HTTP GET.
 *
 * Mutations accepted via GET are a critical CSRF vulnerability because
 * browsers send GET requests cross-origin without preflight.
 */
export async function runGetMethodTamper(
  url: string,
  headers: Record<string, string>,
  primary: GraphQLRequestBody,
): Promise<{ payloads: AttackPayload[]; fuzzHits: FuzzHit[] }> {
  const payloads: AttackPayload[] = [];
  const fuzzHits: FuzzHit[]       = [];

  // Test 1: Send the original query via GET
  const getResult = await _dispatchGet(url, headers, primary);
  const getErrs   = _extractErrors(getResult.body);
  const getHasData = _hasData(getResult.body);

  const getMethodRejected = getResult.status === 405 || getErrs.some(e =>
    e.toLowerCase().includes('get') ||
    e.toLowerCase().includes('method not allowed') ||
    e.toLowerCase().includes('only post'),
  );

  let getOutcome: 'HIT' | 'MISS' | 'BLOCKED' | 'ERROR';
  let getEvidence: string;

  if (getMethodRejected) {
    getOutcome  = 'BLOCKED';
    getEvidence = `Server correctly rejects GET requests: ${getErrs[0]?.slice(0, 200) ?? `HTTP ${getResult.status}`}`;
  } else if (getHasData) {
    getOutcome  = 'HIT';
    getEvidence = `⚠️ Endpoint accepts queries via GET with data returned! Potential CSRF vector if mutations are also accepted.`;
    fuzzHits.push({
      field:    'GET',
      evidence: `GraphQL endpoint at ${url} accepts GET queries — potential CSRF if mutations are allowed via GET`,
      hitType:  'CSRF_METHOD_ACCEPTED',
    });
  } else {
    getOutcome  = 'MISS';
    getEvidence = `GET request sent but no data returned. Status: ${getResult.status}`;
  }

  payloads.push({
    id:         crypto.randomUUID(),
    attackType: 'GET_METHOD_TAMPER',
    sentBody:   primary,
    response:   { status: getResult.status, durationMs: getResult.durationMs, body: getResult.body, raw: getResult.raw },
    outcome:    getOutcome,
    evidence:   getEvidence,
  });

  // Test 2: If original was a mutation, specifically test GET mutation delivery
  const isMutation = /^\s*mutation\b/i.test(primary.query);
  if (isMutation) {
    const mutGetResult = await _dispatchGet(url, headers, primary);
    const mutGetHasData = _hasData(mutGetResult.body);
    const mutGetErrs   = _extractErrors(mutGetResult.body);

    const mutRejected = mutGetResult.status === 405 || mutGetErrs.some(e =>
      e.toLowerCase().includes('mutation') ||
      e.toLowerCase().includes('get') ||
      e.toLowerCase().includes('not allowed'),
    );

    let mutOutcome: 'HIT' | 'MISS' | 'BLOCKED' | 'ERROR';
    let mutEvidence: string;

    if (mutRejected) {
      mutOutcome  = 'BLOCKED';
      mutEvidence = `Server correctly rejects mutations via GET: ${mutGetErrs[0]?.slice(0, 200) ?? `HTTP ${mutGetResult.status}`}`;
    } else if (mutGetHasData) {
      mutOutcome  = 'HIT';
      mutEvidence = `🔴 CRITICAL: Mutation accepted via GET with data returned! Direct CSRF exploitation possible.`;
      fuzzHits.push({
        field:    'GET_MUTATION',
        evidence: `Mutation operation accepted via HTTP GET at ${url} — CSRF vulnerability confirmed`,
        hitType:  'CSRF_METHOD_ACCEPTED',
      });
    } else {
      mutOutcome  = 'MISS';
      mutEvidence = `Mutation sent via GET but no data returned. Status: ${mutGetResult.status}`;
    }

    payloads.push({
      id:         crypto.randomUUID(),
      attackType: 'GET_METHOD_TAMPER',
      sentBody:   primary,
      response:   { status: mutGetResult.status, durationMs: mutGetResult.durationMs, body: mutGetResult.body, raw: mutGetResult.raw },
      outcome:    mutOutcome,
      evidence:   mutEvidence,
    });
  }

  return { payloads, fuzzHits };
}

/**
 * Tests whether the endpoint accepts GraphQL payloads with simple CORS
 * Content-Types that don't trigger preflight OPTIONS requests.
 *
 * Simple types: application/x-www-form-urlencoded, text/plain
 * If accepted, an attacker can submit cross-origin GraphQL requests
 * from a malicious page without CORS preflight blocking them.
 */
export async function runContentTypeCsrf(
  url: string,
  headers: Record<string, string>,
  primary: GraphQLRequestBody,
): Promise<{ payloads: AttackPayload[]; fuzzHits: FuzzHit[] }> {
  const payloads: AttackPayload[] = [];
  const fuzzHits: FuzzHit[]       = [];

  const simpleTypes: { type: string; label: string }[] = [
    { type: 'application/x-www-form-urlencoded', label: 'Form URL-Encoded' },
    { type: 'text/plain',                         label: 'Text/Plain' },
  ];

  for (const { type, label } of simpleTypes) {
    const result = await _dispatchWithContentType(url, headers, primary, type);
    const errs   = _extractErrors(result.body);
    const hasData = _hasData(result.body);

    const contentTypeRejected = errs.some(e =>
      e.toLowerCase().includes('content-type') ||
      e.toLowerCase().includes('unsupported media') ||
      e.toLowerCase().includes('application/json'),
    ) || result.status === 415;

    let outcome: 'HIT' | 'MISS' | 'BLOCKED' | 'ERROR';
    let evidence: string;

    if (contentTypeRejected) {
      outcome  = 'BLOCKED';
      evidence = `Server enforces Content-Type — rejected ${label}: ${errs[0]?.slice(0, 200) ?? `HTTP ${result.status}`}`;
    } else if (hasData) {
      outcome  = 'HIT';
      evidence = `⚠️ Endpoint accepts ${label} Content-Type and returned data! CORS preflight bypass possible.`;
      fuzzHits.push({
        field:    type,
        evidence: `GraphQL endpoint accepts ${label} — no CORS preflight required for cross-origin requests`,
        hitType:  'CSRF_CONTENT_TYPE_ACCEPTED',
      });
    } else if (result.status >= 200 && result.status < 300 && !contentTypeRejected) {
      // 2xx but no data — server processed the request but returned empty
      outcome  = 'HIT';
      evidence = `Server returned ${result.status} for ${label} without explicit rejection. Preflight bypass may work for state-changing operations.`;
      fuzzHits.push({
        field:    type,
        evidence: `Server returned HTTP ${result.status} for ${label} Content-Type — potential preflight bypass`,
        hitType:  'CSRF_CONTENT_TYPE_ACCEPTED',
      });
    } else {
      outcome  = 'MISS';
      evidence = `${label} Content-Type: Status ${result.status}. ${errs[0]?.slice(0, 200) ?? 'No specific rejection.'}`;
    }

    payloads.push({
      id:         crypto.randomUUID(),
      attackType: 'CONTENT_TYPE_CSRF',
      sentBody:   primary,
      response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
      outcome,
      evidence,
    });
  }

  return { payloads, fuzzHits };
}
