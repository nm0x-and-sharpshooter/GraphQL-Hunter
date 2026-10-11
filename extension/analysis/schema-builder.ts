// ─────────────────────────────────────────────────────────────────────────────
// schema-builder.ts — Partial Schema Reconstruction from Captured Traffic (Day 3)
//
// Strategy:
//   For every captured request we have a parsed AST (via query-analyzer).
//   We walk each operation's field accesses and reconstruct which fields
//   exist on which "type" (approximated by the root-level field name),
//   which arguments are used, and in which operation types they appear.
//
// Limitations (by design — no introspection):
//   - We don't know actual GQL type names; we use root field names as proxies.
//   - Nested field ownership is approximated by immediate parent field name.
//   - Types discovered grow monotonically; clear() resets everything.
// ─────────────────────────────────────────────────────────────────────────────

import {
  parse,
  visit,
  Kind,
  FieldNode,
  ArgumentNode,
  OperationDefinitionNode,
} from 'graphql';
import type {
  CapturedRequest,
  SchemaModel,
  SchemaType,
  SchemaField,
  OperationType,
  GraphQLRequestBody,
} from '../types/graphql';

// ── Helpers ───────────────────────────────────────────────────────────────────

export function emptySchemaModel(): SchemaModel {
  return { types: {}, endpoints: [], lastUpdated: Date.now() };
}

function _addEndpoint(model: SchemaModel, url: string): void {
  try {
    const u = new URL(url);
    const ep = u.origin + u.pathname;
    if (!model.endpoints.includes(ep)) {
      model.endpoints.push(ep);
    }
  } catch {
    if (!model.endpoints.includes(url)) model.endpoints.push(url);
  }
}

function _mergeField(
  type: SchemaType,
  fieldName: string,
  args: string[],
  opType: OperationType,
): void {
  if (!type.fields[fieldName]) {
    type.fields[fieldName] = { args: [], seenInOps: [], observationCount: 0 };
  }
  const f: SchemaField = type.fields[fieldName];
  f.observationCount++;

  // Merge new arg names
  for (const arg of args) {
    if (!f.args.includes(arg)) f.args.push(arg);
  }

  // Merge operation type
  if (!f.seenInOps.includes(opType)) f.seenInOps.push(opType);
}

function _ensureType(model: SchemaModel, typeName: string): SchemaType {
  if (!model.types[typeName]) {
    model.types[typeName] = { typeName, fields: {} };
  }
  return model.types[typeName];
}

// ── Core walker ───────────────────────────────────────────────────────────────

/**
 * Walks one GraphQLRequestBody and merges observations into `model`.
 * Uses a stack to track the current "parent type" as we descend into
 * nested selection sets.
 */
function _processBody(
  model: SchemaModel,
  body: GraphQLRequestBody,
  endpoint: string,
): void {
  if (!body.query || typeof body.query !== 'string' || !body.query.trim()) return;

  let documentNode;
  try {
    documentNode = parse(body.query);
  } catch {
    return; // Unparseable — skip silently
  }

  _addEndpoint(model, endpoint);

  // Stack of { typeName, fieldName } to track parent context
  const typeStack: string[] = [];

  visit(documentNode, {
    OperationDefinition: {
      enter(node: OperationDefinitionNode) {
        // Root context — use a synthetic "__Root" type per operation type
        const rootName = `__Root_${node.operation}`;
        typeStack.push(rootName);
        _ensureType(model, rootName);
      },
      leave() {
        typeStack.pop();
      },
    },

    Field: {
      enter(node: FieldNode) {
        const parentTypeName = typeStack[typeStack.length - 1] ?? '__Root_query';
        const parentType     = _ensureType(model, parentTypeName);

        const fieldName = node.name.value;

        // Collect argument names
        const args: string[] = (node.arguments ?? []).map(
          (arg: ArgumentNode) => arg.name.value,
        );

        // Determine op type from stack root
        let opType: OperationType = 'query';
        const root = typeStack[0] ?? '';
        if (root.endsWith('mutation'))     opType = 'mutation';
        else if (root.endsWith('subscription')) opType = 'subscription';

        _mergeField(parentType, fieldName, args, opType);

        // Push this field as the new parent context for nested selections
        typeStack.push(fieldName);
      },
      leave() {
        typeStack.pop();
      },
    },
  });
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Merges a single captured request into an existing SchemaModel (in-place).
 * Returns the mutated model for convenience.
 */
export function mergeRequestIntoSchema(
  model: SchemaModel,
  request: CapturedRequest,
): SchemaModel {
  const bodies: GraphQLRequestBody[] = Array.isArray(request.body)
    ? request.body
    : [request.body];

  for (const body of bodies) {
    _processBody(model, body, request.url);
  }

  model.lastUpdated = Date.now();
  return model;
}

/**
 * Rebuilds a full SchemaModel from scratch given an array of captured requests.
 * Use this on initial load when persisted schema is unavailable.
 */
export function buildSchemaFromRequests(
  requests: CapturedRequest[],
): SchemaModel {
  const model = emptySchemaModel();
  for (const req of requests) {
    mergeRequestIntoSchema(model, req);
  }
  return model;
}

/**
 * Returns summary stats for display in the popup Schema tab.
 */
export interface SchemaSummary {
  typeCount:      number;
  fieldCount:     number;
  endpointCount:  number;
  lastUpdated:    number;
}

export function summariseSchema(model: SchemaModel): SchemaSummary {
  let fieldCount = 0;
  for (const t of Object.values(model.types)) {
    fieldCount += Object.keys(t.fields).length;
  }
  return {
    typeCount:     Object.keys(model.types).length,
    fieldCount,
    endpointCount: model.endpoints.length,
    lastUpdated:   model.lastUpdated,
  };
}

// ── Day 8: SDL Exporter ───────────────────────────────────────────────────────

/**
 * Heuristically maps a field name to a GraphQL scalar or type name.
 * Used to annotate field types in the exported SDL with reasonable guesses.
 */
function _guessFieldType(fieldName: string, args: string[]): string {
  const lower = fieldName.toLowerCase();

  // List indicators — plural names are returned as array types
  const isPlural = lower.endsWith('s') && !lower.endsWith('ss') && lower.length > 3;

  // ID fields
  if (/^(id|uuid|guid|nodeId|_id)$/i.test(fieldName)) return 'ID';
  if (/Id$|_id$/i.test(fieldName)) return 'ID';

  // Boolean fields
  if (/^(is|has|can|should|was|did|enable|disabled|active|deleted|verified|confirmed)/i.test(fieldName)) return 'Boolean';

  // Numeric fields
  if (/^(count|total|limit|offset|page|index|rank|score|amount|price|quantity|size|length|age|width|height|weight|lat|lng|latitude|longitude)/i.test(fieldName)) return 'Int';
  if (/^(ratio|rate|percentage|average|mean|stddev)/i.test(fieldName)) return 'Float';

  // Date/time fields
  if (/^(created|updated|deleted|modified|published|at|date|time|timestamp|expires|issued)/i.test(fieldName)) return 'String';
  if (/(At|Date|Time|Timestamp)$/.test(fieldName)) return 'String';

  // Known complex types  — return title-cased field name as a type reference
  if (args.length > 0 || isPlural) {
    // Derive type name: strip trailing 's', capitalise
    const base = isPlural ? fieldName.slice(0, -1) : fieldName;
    const typeName = base.charAt(0).toUpperCase() + base.slice(1);
    return isPlural ? `[${typeName}]` : typeName;
  }

  // Default scalar
  return 'String';
}

/**
 * Converts a SchemaModel (reconstructed from captured traffic, no introspection)
 * into a valid GraphQL Schema Definition Language (SDL) string.
 *
 * The output is annotated with comments indicating the reconstruction provenance
 * and is suitable for use in Apollo Workbench, GraphQL Inspector, or similar tools.
 */
export function exportSchemaAsSDL(model: SchemaModel, endpoint?: string): string {
  const lines: string[] = [];
  const now = new Date().toISOString();

  lines.push(`# ─────────────────────────────────────────────────────────────────`);
  lines.push(`# Reconstructed by GraphQL Hunter (Zero-Introspection Schema)`);
  if (endpoint) lines.push(`# Target Endpoint: ${endpoint}`);
  lines.push(`# Exported: ${now}`);
  lines.push(`# NOTE: Type names and field types are heuristically inferred.`);
  lines.push(`#        Verify against the actual API before relying on this schema.`);
  lines.push(`# ─────────────────────────────────────────────────────────────────`);
  lines.push('');

  // Separate root types from nested types
  const rootQueryType  = model.types['__Root_query'];
  const rootMutType    = model.types['__Root_mutation'];
  const rootSubType    = model.types['__Root_subscription'];
  const nestedTypes    = Object.entries(model.types).filter(
    ([k]) => !k.startsWith('__Root_'),
  );

  // ── Emit Query type ────────────────────────────────────────────────────────
  if (rootQueryType && Object.keys(rootQueryType.fields).length > 0) {
    lines.push('type Query {');
    for (const [fieldName, fieldMeta] of Object.entries(rootQueryType.fields).sort()) {
      const argsStr = fieldMeta.args.length > 0
        ? `(${fieldMeta.args.map(a => `${a}: String`).join(', ')})`
        : '';
      const returnType = _guessFieldType(fieldName, fieldMeta.args);
      const obs = fieldMeta.observationCount;
      lines.push(`  # observed ${obs}x`);
      lines.push(`  ${fieldName}${argsStr}: ${returnType}`);
    }
    lines.push('}');
    lines.push('');
  }

  // ── Emit Mutation type ─────────────────────────────────────────────────────
  if (rootMutType && Object.keys(rootMutType.fields).length > 0) {
    lines.push('type Mutation {');
    for (const [fieldName, fieldMeta] of Object.entries(rootMutType.fields).sort()) {
      const argsStr = fieldMeta.args.length > 0
        ? `(${fieldMeta.args.map(a => `${a}: String`).join(', ')})`
        : '';
      const returnType = _guessFieldType(fieldName, fieldMeta.args);
      const obs = fieldMeta.observationCount;
      lines.push(`  # observed ${obs}x`);
      lines.push(`  ${fieldName}${argsStr}: ${returnType}`);
    }
    lines.push('}');
    lines.push('');
  }

  // ── Emit Subscription type ─────────────────────────────────────────────────
  if (rootSubType && Object.keys(rootSubType.fields).length > 0) {
    lines.push('type Subscription {');
    for (const [fieldName, fieldMeta] of Object.entries(rootSubType.fields).sort()) {
      const argsStr = fieldMeta.args.length > 0
        ? `(${fieldMeta.args.map(a => `${a}: String`).join(', ')})`
        : '';
      const returnType = _guessFieldType(fieldName, fieldMeta.args);
      lines.push(`  ${fieldName}${argsStr}: ${returnType}`);
    }
    lines.push('}');
    lines.push('');
  }

  // ── Emit nested/object types ───────────────────────────────────────────────
  for (const [typeName, schemaType] of nestedTypes.sort((a, b) => a[0].localeCompare(b[0]))) {
    if (Object.keys(schemaType.fields).length === 0) continue;

    // Derive a clean type name (title-case the field name used as proxy)
    const cleanName = typeName.charAt(0).toUpperCase() + typeName.slice(1);
    lines.push(`# Inferred object type (proxied from field name "${typeName}")`);
    lines.push(`type ${cleanName} {`);
    for (const [fieldName, fieldMeta] of Object.entries(schemaType.fields).sort()) {
      const argsStr = fieldMeta.args.length > 0
        ? `(${fieldMeta.args.map(a => `${a}: String`).join(', ')})`
        : '';
      const returnType = _guessFieldType(fieldName, fieldMeta.args);
      lines.push(`  ${fieldName}${argsStr}: ${returnType}`);
    }
    lines.push('}');
    lines.push('');
  }

  return lines.join('\n');
}
