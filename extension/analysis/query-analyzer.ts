// ─────────────────────────────────────────────────────────────────────────────
// query-analyzer.ts — AST-based GraphQL Query Parser & Analyzer
//
// Parses captured query strings into ASTs using the official `graphql` parser,
// extracts accessed fields, arguments, variables, and operation metadata,
// and invokes the risk scorer + complexity scorer to assign security risk levels.
// ─────────────────────────────────────────────────────────────────────────────

import {
  parse,
  visit,
  OperationDefinitionNode,
  FieldNode,
  ArgumentNode,
  VariableDefinitionNode,
  Kind,
} from 'graphql';
import type {
  FieldAccess,
  QueryAnalysis,
  RequestAnalysis,
  GraphQLRequestBody,
  CapturedRequest,
  OperationType,
} from '../types/graphql';
import { scoreQuery, highestRisk } from './risk-scorer';
import { scoreComplexity }        from './complexity-scorer';

const ID_ARG_REGEX = /^(id|.*Id|.*_id|uuid|guid|key|pk|nodeId)$/i;

/**
 * Parses a single GraphQLRequestBody and extracts QueryAnalysis for each operation.
 */
export function analyzeQuery(body: GraphQLRequestBody): QueryAnalysis[] {
  if (!body.query || typeof body.query !== 'string' || body.query.trim().length === 0) {
    return [createEmptyAnalysis(body, 'Empty Query', 'The query payload was empty or missing.')];
  }

  let documentNode;
  try {
    documentNode = parse(body.query);
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    return [createEmptyAnalysis(body, 'GraphQL Parse Error', errorMsg)];
  }

  const operations: OperationDefinitionNode[] = [];
  for (const def of documentNode.definitions) {
    if (def.kind === Kind.OPERATION_DEFINITION) {
      operations.push(def);
    }
  }

  // If no operations found (e.g. document only contains fragments)
  if (operations.length === 0) {
    return [createEmptyAnalysis(body, 'No Operations', 'Document contains no executable operations.')];
  }

  // If specific operationName requested, prioritize matching operation if present
  let targetOps = operations;
  if (body.operationName) {
    const matched = operations.filter(op => op.name?.value === body.operationName);
    if (matched.length > 0) {
      targetOps = matched;
    }
  }

  return targetOps.map(op => analyzeOperation(op, body));
}

/**
 * Analyzes an individual OperationDefinitionNode.
 */
function analyzeOperation(
  op: OperationDefinitionNode,
  body: GraphQLRequestBody,
): QueryAnalysis {
  const opType: OperationType =
    op.operation === 'query' || op.operation === 'mutation' || op.operation === 'subscription'
      ? op.operation
      : 'unknown';

  const opName = op.name?.value ?? body.operationName ?? 'anonymous';

  // Extract variables from variable definitions and body.variables
  const varSet = new Set<string>();
  if (op.variableDefinitions) {
    for (const varDef of op.variableDefinitions) {
      varSet.add(varDef.variable.name.value);
    }
  }
  if (body.variables && typeof body.variables === 'object') {
    for (const key of Object.keys(body.variables)) {
      varSet.add(key);
    }
  }
  const variables = Array.from(varSet);

  // Traverse AST to collect field accesses
  const fields: FieldAccess[] = [];

  visit(op, {
    [Kind.FIELD]: (node: FieldNode) => {
      const fieldName = node.name.value;
      const hasIdArg = (node.arguments ?? []).some((arg: ArgumentNode) =>
        ID_ARG_REGEX.test(arg.name.value),
      );
      fields.push({ fieldName, hasIdArg });
    },
  });

  const complexity = scoreComplexity(op);

  const findings = scoreQuery({
    operationType: opType,
    operationName: opName,
    fields,
    variables,
    body,
    complexity,
  });

  const riskLevel = highestRisk(findings.map(f => f.level));

  return {
    operationType: opType,
    operationName: opName,
    fields,
    variables,
    findings,
    riskLevel,
    fieldCount: fields.length,
    complexity,
  };
}

/**
 * Fallback analysis for unparseable or empty queries.
 */
function createEmptyAnalysis(
  body: GraphQLRequestBody,
  findingTitle: string,
  findingDetail: string,
): QueryAnalysis {
  const opType: OperationType = body.query
    ? body.query.trim().toLowerCase().startsWith('mutation')
      ? 'mutation'
      : body.query.trim().toLowerCase().startsWith('subscription')
      ? 'subscription'
      : 'query'
    : 'unknown';

  const opName = body.operationName ?? 'unknown';
  const variables = body.variables ? Object.keys(body.variables) : [];

  const findings = [
    ...scoreQuery({
      operationType: opType,
      operationName: opName,
      fields: [],
      variables,
      body,
    }),
    {
      level: 'INFO' as const,
      title: findingTitle,
      detail: findingDetail,
    },
  ];

  return {
    operationType: opType,
    operationName: opName,
    fields: [],
    variables,
    findings,
    riskLevel: highestRisk(findings.map(f => f.level)),
    fieldCount: 0,
  };
}

/**
 * Analyzes a full CapturedRequest (handles single & batched requests)
 * and produces a RequestAnalysis.
 */
export function analyzeRequest(request: CapturedRequest): RequestAnalysis {
  const bodies: GraphQLRequestBody[] = Array.isArray(request.body)
    ? request.body
    : [request.body];

  const operations: QueryAnalysis[] = [];
  for (const b of bodies) {
    operations.push(...analyzeQuery(b));
  }

  const overallRisk = highestRisk(operations.map(op => op.riskLevel));
  return { operations, overallRisk };
}
