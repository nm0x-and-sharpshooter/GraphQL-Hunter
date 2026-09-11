// ─────────────────────────────────────────────────────────────────────────────
// risk-scorer.ts — Heuristic security risk scoring for captured GraphQL ops
//
// Each rule produces a RiskFinding. Callers aggregate findings across
// operations to determine the overall request risk level.
// ─────────────────────────────────────────────────────────────────────────────

import type {
  RiskLevel,
  RiskFinding,
  FieldAccess,
  GraphQLRequestBody,
  OperationType,
} from '../types/graphql';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ScoreInput {
  operationType: OperationType;
  operationName: string;
  fields:        FieldAccess[];
  variables:     string[];
  body:          GraphQLRequestBody;
}

// ── Patterns ──────────────────────────────────────────────────────────────────

/** Variable/argument names that indicate object ID access (BOLA surface). */
const ID_PATTERN = /^(id|.*Id|.*_id|uuid|guid|key|pk|nodeId)$/;

/** GraphQL introspection field names that reveal the schema. */
const INTROSPECTION = new Set(['__schema', '__type', '__typename', '__InputValue', '__Field', '__EnumValue']);

// ── Scorer ────────────────────────────────────────────────────────────────────

export function scoreQuery(input: ScoreInput): RiskFinding[] {
  const findings: RiskFinding[] = [];
  const { operationType, operationName, fields, variables, body } = input;

  const fieldNames = fields.map(f => f.fieldName);

  // ── HIGH: Introspection ────────────────────────────────────────────────────
  const isIntrospection =
    fieldNames.some(f => INTROSPECTION.has(f)) ||
    body.query.includes('__schema')             ||
    body.query.includes('__type');

  if (isIntrospection) {
    findings.push({
      level:  'HIGH',
      title:  'Introspection Query',
      detail: 'Schema introspection exposes the full API surface — a common first step in GraphQL reconnaissance.',
    });
  }

  // ── CRITICAL: BOLA in Mutation ────────────────────────────────────────────
  const idVars = variables.filter(v => ID_PATTERN.test(v));
  if (operationType === 'mutation' && idVars.length > 0) {
    findings.push({
      level:  'CRITICAL',
      title:  'Potential BOLA in Mutation',
      detail: `"${operationName}" mutates object(s) by ID [${idVars.join(', ')}] — test whether other users' IDs are accepted.`,
    });
  }

  // ── MEDIUM: Object ID in Query ────────────────────────────────────────────
  if (operationType === 'query' && idVars.length > 0) {
    findings.push({
      level:  'MEDIUM',
      title:  'Object Lookup by ID',
      detail: `"${operationName}" fetches by ID [${idVars.join(', ')}] — verify server-side authorisation checks.`,
    });
  }

  // ── MEDIUM: Field-level ID arguments (when not already CRITICAL) ──────────
  const idArgFields = fields.filter(f => f.hasIdArg);
  if (idArgFields.length > 0 && !findings.some(f => f.level === 'CRITICAL')) {
    findings.push({
      level:  'MEDIUM',
      title:  'ID Arguments on Fields',
      detail: `Fields [${idArgFields.map(f => f.fieldName).join(', ')}] accept ID arguments — potential horizontal privilege escalation.`,
    });
  }

  // ── LOW: Over-fetching (>20 fields) ──────────────────────────────────────
  if (fields.length > 20) {
    findings.push({
      level:  'LOW',
      title:  'Excessive Field Count',
      detail: `${fields.length} fields selected — potential data over-exposure or DoS amplification.`,
    });
  }

  // ── INFO: Anonymous operation ─────────────────────────────────────────────
  if (!body.operationName) {
    findings.push({
      level:  'INFO',
      title:  'Anonymous Operation',
      detail: 'No operation name makes server-side rate-limiting and audit logging harder.',
    });
  }

  return findings;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RISK_ORDER: RiskLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** Returns the highest risk level from a list. */
export function highestRisk(levels: RiskLevel[]): RiskLevel {
  for (const level of RISK_ORDER) {
    if (levels.includes(level)) return level;
  }
  return 'INFO';
}
