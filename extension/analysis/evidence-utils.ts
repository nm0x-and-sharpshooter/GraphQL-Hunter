// ─────────────────────────────────────────────────────────────────────────────
// evidence-utils.ts — Pure evidence utility functions (Day 5)
//
// No browser API dependencies — all functions are pure transformations so they
// can be imported in both the background service worker and the dashboard page.
//
// Exports:
//   severityScore(verdict)           → SeverityScore (0|1|2)
//   generateCurl(request, testType)  → curl command string
//   generateMarkdownReport(findings) → Markdown string
//   generateJsonReport(findings)     → JSON string
// ─────────────────────────────────────────────────────────────────────────────

import type {
  AuthVerdict,
  AuthTestType,
  CapturedRequest,
  Finding,
  SeverityScore,
  GraphQLRequestBody,
} from '../types/graphql';

// ── Severity ranking ──────────────────────────────────────────────────────────

/**
 * Maps an AuthVerdict to a numeric severity rank used for sorting.
 *   VULNERABLE    → 2  (highest — confirmed auth bypass)
 *   INCONCLUSIVE  → 1  (needs manual review)
 *   PROTECTED     → 0  (lowest — server enforces auth)
 */
export function severityScore(verdict: AuthVerdict): SeverityScore {
  switch (verdict) {
    case 'VULNERABLE':   return 2;
    case 'INCONCLUSIVE': return 1;
    case 'PROTECTED':    return 0;
  }
}

// ── cURL generator ────────────────────────────────────────────────────────────

const AUTH_HEADERS = new Set([
  'authorization',
  'x-auth-token',
  'x-access-token',
  'x-api-key',
  'bearer',
  'token',
]);

/** Escapes a string for safe embedding inside single-quoted shell strings. */
function _shellEscape(s: string): string {
  // Replace single quotes with '\''
  return s.replace(/'/g, `'\\''`);
}

/**
 * Reconstructs the replayed request as a terminal curl command.
 * The generated command reflects the *replayed* variant (stripped auth) so
 * testers can directly reproduce the vulnerability from a terminal.
 */
export function generateCurl(
  request:  CapturedRequest,
  testType: AuthTestType,
): string {
  const lines: string[] = ['curl -s -X POST'];

  // Build headers (mirror the stripping logic from auth-tester)
  for (const [k, v] of Object.entries(request.requestHeaders)) {
    const lower = k.toLowerCase();
    if (testType === 'NO_AUTH' || testType === 'STRIP_COOKIES') {
      if (AUTH_HEADERS.has(lower) || lower === 'cookie') continue;
    }
    lines.push(`  -H '${_shellEscape(k)}: ${_shellEscape(v)}'`);
  }

  // Always include Content-Type
  const hasContentType = Object.keys(request.requestHeaders)
    .some(k => k.toLowerCase() === 'content-type');
  if (!hasContentType) {
    lines.push(`  -H 'Content-Type: application/json'`);
  }

  // Build body
  let body: unknown = request.body;
  if (testType === 'MUTATE_ID') {
    const mutate = (op: GraphQLRequestBody): GraphQLRequestBody => {
      if (!op.variables) return op;
      const mutated = { ...op.variables };
      for (const [k, v] of Object.entries(mutated)) {
        if (!/^(id|.*Id|.*_id|uuid|guid|key|pk|nodeId)$/i.test(k)) continue;
        if (typeof v === 'number') {
          mutated[k] = v + 1;
        } else if (typeof v === 'string') {
          const n = parseInt(v, 10);
          if (!isNaN(n)) {
            mutated[k] = String(n + 1);
          } else {
            mutated[k] = v.slice(0, -1) + ((parseInt(v.slice(-1), 16) + 1) % 16).toString(16);
          }
        }
      }
      return { ...op, variables: mutated };
    };
    body = Array.isArray(request.body)
      ? request.body.map(mutate)
      : mutate(request.body);
  }

  lines.push(`  --data '${_shellEscape(JSON.stringify(body))}'`);
  lines.push(`  '${_shellEscape(request.url)}'`);

  return lines.join(' \\\n');
}

// ── Report generators ─────────────────────────────────────────────────────────

const VERDICT_EMOJI: Record<AuthVerdict, string> = {
  VULNERABLE:   '🔴',
  INCONCLUSIVE: '🟡',
  PROTECTED:    '🟢',
};

const TEST_LABEL: Record<AuthTestType, string> = {
  NO_AUTH:       'No Auth (strip Authorization + cookies)',
  STRIP_COOKIES: 'Strip Cookies only',
  MUTATE_ID:     'Mutate ID variables (BOLA/IDOR)',
};

/**
 * Generates a Markdown security report for all findings.
 * Format is modelled after CVE advisories — heading per finding,
 * evidence block, leaked fields, and reproduction steps.
 */
export function generateMarkdownReport(findings: Finding[]): string {
  const now = new Date().toISOString();
  const vulnCount    = findings.filter(f => f.result.verdict === 'VULNERABLE').length;
  const inconcCount  = findings.filter(f => f.result.verdict === 'INCONCLUSIVE').length;
  const protCount    = findings.filter(f => f.result.verdict === 'PROTECTED').length;

  const lines: string[] = [
    '# GraphQL Hunter — Authorization Test Report',
    '',
    `**Generated:** ${now}  `,
    `**Total Findings:** ${findings.length}  `,
    `**Vulnerable:** ${vulnCount} | **Inconclusive:** ${inconcCount} | **Protected:** ${protCount}`,
    '',
    '---',
    '',
  ];

  // Sort: VULNERABLE first, then INCONCLUSIVE, then PROTECTED; newest within each
  const sorted = [...findings].sort((a, b) => {
    if (b.severityScore !== a.severityScore) return b.severityScore - a.severityScore;
    return b.result.testedAt - a.result.testedAt;
  });

  for (let i = 0; i < sorted.length; i++) {
    const f   = sorted[i];
    const res = f.result;
    const emoji = VERDICT_EMOJI[res.verdict];

    lines.push(`## ${i + 1}. ${emoji} [${res.verdict}] ${f.operationName}`);
    lines.push('');
    lines.push(`| Field | Value |`);
    lines.push(`|---|---|`);
    lines.push(`| **Endpoint** | \`${f.requestUrl}\` |`);
    lines.push(`| **Operation** | \`${f.operationName}\` |`);
    lines.push(`| **Test Type** | ${TEST_LABEL[res.testType]} |`);
    lines.push(`| **Verdict** | **${res.verdict}** |`);
    lines.push(`| **HTTP Status** | ${res.replayedStatus} |`);
    lines.push(`| **Duration** | ${res.replayedDurationMs}ms |`);
    lines.push(`| **Tested At** | ${new Date(res.testedAt).toISOString()} |`);
    lines.push('');

    lines.push('### Evidence');
    lines.push('');
    lines.push(`> ${res.evidence}`);
    lines.push('');

    if (res.diff.leakedFields.length > 0) {
      lines.push('### Leaked Fields');
      lines.push('');
      for (const field of res.diff.leakedFields) {
        lines.push(`- \`${field}\``);
      }
      lines.push('');
    }

    const changedEntries = res.diff.entries.filter(e => e.changed).slice(0, 10);
    if (changedEntries.length > 0) {
      lines.push('### Response Diff (first 10 changed fields)');
      lines.push('');
      lines.push('| Path | Original | Replayed |');
      lines.push('|---|---|---|');
      for (const e of changedEntries) {
        lines.push(`| \`${e.path}\` | ${JSON.stringify(e.originalValue)} | ${JSON.stringify(e.replayedValue)} |`);
      }
      lines.push('');
    }

    lines.push('### Reproduction');
    lines.push('');
    lines.push('```bash');
    lines.push(f.curl);
    lines.push('```');
    lines.push('');

    if (f.note) {
      lines.push('### Analyst Notes');
      lines.push('');
      lines.push(f.note);
      lines.push('');
    }

    lines.push('---');
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Generates a clean JSON dump of all findings.
 * Suitable for ingestion into JIRA, Burp, or custom pipelines.
 */
export function generateJsonReport(findings: Finding[]): string {
  const report = {
    generatedAt: new Date().toISOString(),
    tool:        'GraphQL Hunter',
    version:     '0.1.0',
    summary: {
      total:        findings.length,
      vulnerable:   findings.filter(f => f.result.verdict === 'VULNERABLE').length,
      inconclusive: findings.filter(f => f.result.verdict === 'INCONCLUSIVE').length,
      protected:    findings.filter(f => f.result.verdict === 'PROTECTED').length,
    },
    findings,
  };
  return JSON.stringify(report, null, 2);
}
