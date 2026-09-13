// ─────────────────────────────────────────────────────────────────────────────
// complexity-scorer.ts — Query complexity analysis (Day 3)
//
// Computes a ComplexityScore for a parsed GraphQL operation by walking the
// selection set AST and measuring:
//   - Maximum nesting depth
//   - Total field count
//   - List-field multipliers (fields likely returning arrays amplify cost)
//   - Estimated server-side cost = sum(depth_of_field × list_multiplier)
//
// Thresholds:
//   depth  > 5  → isHighComplexity = true
//   cost   > 100 → isHighComplexity = true
// ─────────────────────────────────────────────────────────────────────────────

import {
  SelectionSetNode,
  FieldNode,
  InlineFragmentNode,
  FragmentSpreadNode,
  Kind,
} from 'graphql';
import type { OperationDefinitionNode } from 'graphql';
import type { ComplexityScore } from '../types/graphql';

// ── Constants ─────────────────────────────────────────────────────────────────

/** Fields whose names strongly suggest they return a list (multiplier applied). */
const LIST_FIELD_RE = /^(list|all|search|find|filter|get[A-Z].*s$|.*[Ll]ist$|.*[Nn]odes$|.*[Ee]dges$|.*[Ii]tems$|.*[Rr]esults$|.*[Cc]onnection$)/;

const DEPTH_THRESHOLD = 5;
const COST_THRESHOLD  = 100;

/** Cost multiplier applied when a field name matches the list pattern. */
const LIST_MULTIPLIER = 3;

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Computes a ComplexityScore for a single OperationDefinitionNode.
 * Call once per operation — `analyzeOperation` in query-analyzer.ts wires this.
 */
export function scoreComplexity(op: OperationDefinitionNode): ComplexityScore {
  if (!op.selectionSet) {
    return { depth: 0, fieldCount: 0, estimatedCost: 0, isHighComplexity: false };
  }

  const result = _walkSelectionSet(op.selectionSet, 0);

  const isHighComplexity =
    result.maxDepth      > DEPTH_THRESHOLD ||
    result.estimatedCost > COST_THRESHOLD;

  return {
    depth:            result.maxDepth,
    fieldCount:       result.fieldCount,
    estimatedCost:    Math.round(result.estimatedCost),
    isHighComplexity,
  };
}

// ── AST walker ────────────────────────────────────────────────────────────────

interface WalkResult {
  maxDepth:      number;
  fieldCount:    number;
  estimatedCost: number;
}

function _walkSelectionSet(
  selSet: SelectionSetNode,
  currentDepth: number,
): WalkResult {
  let maxDepth      = currentDepth;
  let fieldCount    = 0;
  let estimatedCost = 0;

  for (const selection of selSet.selections) {
    if (selection.kind === Kind.FIELD) {
      const field = selection as FieldNode;
      fieldCount++;

      const isList       = LIST_FIELD_RE.test(field.name.value);
      const multiplier   = isList ? LIST_MULTIPLIER : 1;
      const fieldCost    = (currentDepth + 1) * multiplier;
      estimatedCost     += fieldCost;

      if (field.selectionSet) {
        const child = _walkSelectionSet(field.selectionSet, currentDepth + 1);
        maxDepth       = Math.max(maxDepth, child.maxDepth);
        fieldCount    += child.fieldCount;
        estimatedCost += child.estimatedCost * multiplier;
      } else {
        maxDepth = Math.max(maxDepth, currentDepth + 1);
      }
    } else if (selection.kind === Kind.INLINE_FRAGMENT) {
      const frag = selection as InlineFragmentNode;
      if (frag.selectionSet) {
        const child = _walkSelectionSet(frag.selectionSet, currentDepth);
        maxDepth       = Math.max(maxDepth, child.maxDepth);
        fieldCount    += child.fieldCount;
        estimatedCost += child.estimatedCost;
      }
    } else if (selection.kind === Kind.FRAGMENT_SPREAD) {
      // FragmentSpread — we can't resolve fragments here (no document context),
      // so conservatively add a flat cost of 5 per spread.
      const _spread = selection as FragmentSpreadNode;
      void _spread;
      estimatedCost += 5;
      fieldCount    += 1;
    }
  }

  return { maxDepth, fieldCount, estimatedCost };
}
