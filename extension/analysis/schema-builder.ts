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
