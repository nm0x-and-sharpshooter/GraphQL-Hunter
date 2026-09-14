// ─────────────────────────────────────────────────────────────────────────────
// response-comparator.ts — Field-level diff engine for GraphQL responses (Day 4)
//
// Usage:
//   const diff = compareResponses(originalBody, replayedBody);
//   const vuln = isVulnerable(diff);
//
// Algorithm:
//   1. Walk both response objects recursively.
//   2. At every leaf, record a ResponseDiffEntry (path, original, replayed, changed).
//   3. "Leaked fields" = paths where replayedValue is non-null/non-empty
//      (data returned without auth).
//   4. VULNERABLE when leakedFields.length > 0
// ─────────────────────────────────────────────────────────────────────────────

import type { ResponseDiff, ResponseDiffEntry } from '../types/graphql';

// ── Helpers ───────────────────────────────────────────────────────────────────

function isNullLike(v: unknown): boolean {
  if (v === null || v === undefined) return true;
  if (Array.isArray(v) && v.length === 0) return true;
  if (typeof v === 'object' && v !== null && Object.keys(v as object).length === 0) return true;
  return false;
}

/** Deep-equality check — sufficient for JSON primitives and plain objects. */
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, (b as unknown[])[i]));
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const aKeys = Object.keys(a as object).sort();
    const bKeys = Object.keys(b as object).sort();
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every(k =>
      deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
    );
  }
  return false;
}

// ── Core walker ───────────────────────────────────────────────────────────────

function _walk(
  orig:     unknown,
  replayed: unknown,
  path:     string,
  entries:  ResponseDiffEntry[],
): void {
  // Both are primitives (or null) — emit a leaf entry
  if (
    typeof orig !== 'object' || orig === null ||
    typeof replayed !== 'object' || replayed === null
  ) {
    entries.push({
      path,
      originalValue:  orig,
      replayedValue:  replayed,
      changed:        !deepEqual(orig, replayed),
    });
    return;
  }

  if (Array.isArray(orig) || Array.isArray(replayed)) {
    // Treat arrays as a single leaf for simplicity (length comparison)
    entries.push({
      path,
      originalValue:  orig,
      replayedValue:  replayed,
      changed:        !deepEqual(orig, replayed),
    });
    return;
  }

  // Both are plain objects — recurse over union of keys
  const origObj     = orig     as Record<string, unknown>;
  const replayedObj = replayed as Record<string, unknown>;
  const allKeys     = new Set([...Object.keys(origObj), ...Object.keys(replayedObj)]);

  for (const key of allKeys) {
    _walk(origObj[key], replayedObj[key], path ? `${path}.${key}` : key, entries);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Compares two GraphQL response data objects field-by-field.
 *
 * Pass the `.data` property from each response body.
 */
export function compareResponses(
  originalData: unknown,
  replayedData: unknown,
): ResponseDiff {
  const entries: ResponseDiffEntry[] = [];
  _walk(originalData ?? null, replayedData ?? null, 'data', entries);

  // Leaked fields: paths where the replayed response has meaningful data
  const leakedFields: string[] = entries
    .filter(e => !isNullLike(e.replayedValue))
    .map(e => e.path);

  const fullyIdentical = entries.every(e => !e.changed);

  return { entries, leakedFields, fullyIdentical };
}

/**
 * Returns true when a replayed response (without auth) contained meaningful data,
 * indicating the server is not enforcing authorization.
 */
export function isVulnerable(diff: ResponseDiff): boolean {
  return diff.leakedFields.length > 0;
}
