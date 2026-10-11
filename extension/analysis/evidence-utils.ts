// ─────────────────────────────────────────────────────────────────────────────
// evidence-utils.ts — Pure evidence utility functions (Day 5 + Day 8)
//
// No browser API dependencies — all functions are pure transformations so they
// can be imported in both the background service worker and the dashboard page.
//
// Exports (Day 5):
//   severityScore(verdict)              → SeverityScore (0|1|2)
//   generateCurl(request, testType)     → curl command string
//   generateMarkdownReport(findings)    → Markdown string
//   generateJsonReport(findings)        → JSON string
//
// Exports (Day 8 — Toolchain Interoperability):
//   exportPostmanCollection(requests)   → Postman Collection v2.1 JSON string
//   exportBurpRawRequests(requests)     → Burp/Caido raw HTTP text
//   exportHtmlAuditReport(findings, jobs) → Self-contained HTML executive report
// ─────────────────────────────────────────────────────────────────────────────

import type {
  AuthVerdict,
  AuthTestType,
  CapturedRequest,
  Finding,
  SeverityScore,
  GraphQLRequestBody,
  AttackJob,
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

// ── Day 8: Toolchain Interoperability Exporters ───────────────────────────────

/**
 * Exports all captured GraphQL requests as a Postman Collection v2.1 JSON file.
 * Requests are grouped into Query/Mutation/Subscription folders.
 * Each item includes headers, URL, and pre-set body with the actual GraphQL payload.
 */
export function exportPostmanCollection(
  requests:   CapturedRequest[],
  targetName: string = 'GraphQL Hunter — Captured Requests',
): string {
  const now = new Date().toISOString();

  // Build Postman items, grouped by operation type
  const queryItems:    object[] = [];
  const mutationItems: object[] = [];
  const otherItems:    object[] = [];

  for (const req of requests) {
    const bodies: GraphQLRequestBody[] = Array.isArray(req.body) ? req.body : [req.body];
    const opName = req.analysis?.operations[0]?.operationName
      ?? bodies[0]?.operationName
      ?? 'anonymous';
    const opType = req.analysis?.operations[0]?.operationType ?? 'query';

    // Build Postman request headers array
    const headerList = Object.entries(req.requestHeaders)
      .filter(([k]) => k.toLowerCase() !== 'content-length')
      .map(([k, v]) => ({ key: k, value: v }));

    const hasContentType = headerList.some(h => h.key.toLowerCase() === 'content-type');
    if (!hasContentType) {
      headerList.push({ key: 'Content-Type', value: 'application/json' });
    }

    // Parse URL
    let urlObj: { raw: string; host: string[]; path: string[] };
    try {
      const u = new URL(req.url);
      urlObj = {
        raw: req.url,
        host: u.hostname.split('.'),
        path: u.pathname.split('/').filter(Boolean),
      };
    } catch {
      urlObj = { raw: req.url, host: [req.url], path: [] };
    }

    const bodyPayload = Array.isArray(req.body) ? req.body : req.body;

    const item = {
      name: `${opName} [${opType}]`,
      request: {
        method: req.method || 'POST',
        header: headerList,
        url:    urlObj,
        body: {
          mode: 'raw',
          raw:  JSON.stringify(bodyPayload, null, 2),
          options: { raw: { language: 'json' } },
        },
        description: `Captured by GraphQL Hunter at ${new Date(req.timestamp).toISOString()}`,
      },
    };

    if (opType === 'mutation') {
      mutationItems.push(item);
    } else if (opType === 'query' || opType === 'subscription') {
      queryItems.push(item);
    } else {
      otherItems.push(item);
    }
  }

  const collection = {
    info: {
      name:        targetName,
      description: `Exported by GraphQL Hunter on ${now}. Contains ${requests.length} captured GraphQL requests.`,
      schema:      'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
    },
    item: [
      ...(queryItems.length > 0    ? [{ name: 'Queries',       item: queryItems    }] : []),
      ...(mutationItems.length > 0 ? [{ name: 'Mutations',     item: mutationItems }] : []),
      ...(otherItems.length > 0    ? [{ name: 'Subscriptions', item: otherItems    }] : []),
    ],
    variable: [
      { key: 'baseUrl', value: requests[0]?.url ?? '', type: 'string' },
    ],
  };

  return JSON.stringify(collection, null, 2);
}

/**
 * Exports all captured GraphQL requests as raw HTTP/1.1 request texts.
 * The output is formatted for direct pasting into Burp Suite Repeater or Caido Replay.
 * Each request is separated by a comment header and blank lines.
 */
export function exportBurpRawRequests(requests: CapturedRequest[]): string {
  const blocks: string[] = [];
  const now = new Date().toISOString();

  blocks.push(`# GraphQL Hunter — Burp Suite / Caido Raw Requests`);
  blocks.push(`# Exported: ${now}`);
  blocks.push(`# Total: ${requests.length} request(s)`);
  blocks.push(`# Usage: Paste each block into Burp Repeater or Caido Replay`);
  blocks.push('');

  for (let i = 0; i < requests.length; i++) {
    const req = requests[i];
    const bodies: GraphQLRequestBody[] = Array.isArray(req.body) ? req.body : [req.body];
    const opName = req.analysis?.operations[0]?.operationName
      ?? bodies[0]?.operationName
      ?? 'anonymous';

    let parsedUrl: URL | null = null;
    try { parsedUrl = new URL(req.url); } catch { /* ignore */ }

    const host = parsedUrl?.host ?? req.url;
    const pathAndQuery = parsedUrl ? parsedUrl.pathname + parsedUrl.search : '/';
    const bodyStr = JSON.stringify(req.body);
    const contentLength = new TextEncoder().encode(bodyStr).length;

    const block: string[] = [];
    block.push(`# ── Request ${i + 1}: ${opName} ──`);
    block.push(`# URL: ${req.url}`);
    block.push(`# Captured: ${new Date(req.timestamp).toISOString()}`);
    block.push('');
    block.push(`POST ${pathAndQuery} HTTP/1.1`);
    block.push(`Host: ${host}`);

    // Emit captured headers
    for (const [k, v] of Object.entries(req.requestHeaders)) {
      const lower = k.toLowerCase();
      if (lower === 'content-length' || lower === 'transfer-encoding') continue;
      block.push(`${k}: ${v}`);
    }

    // Ensure required headers
    const hasContentType = Object.keys(req.requestHeaders).some(k => k.toLowerCase() === 'content-type');
    if (!hasContentType) block.push('Content-Type: application/json');
    block.push(`Content-Length: ${contentLength}`);
    block.push('Connection: close');
    block.push('');
    block.push(bodyStr);
    block.push('');

    blocks.push(block.join('\n'));
    blocks.push('─'.repeat(80));
    blocks.push('');
  }

  return blocks.join('\n');
}

// ── HTML Audit Report helpers ─────────────────────────────────────────────────

const CVSS_MAP: Record<string, { score: string; rating: string; color: string }> = {
  VULNERABLE:   { score: '9.8', rating: 'CRITICAL', color: '#f38ba8' },
  INCONCLUSIVE: { score: '5.0', rating: 'MEDIUM',   color: '#fab387' },
  PROTECTED:    { score: '0.0', rating: 'NONE',      color: '#a6e3a1' },
};

const REMEDIATION: Record<string, string> = {
  NO_AUTH:       'Enforce server-side authentication on every resolver. Never trust client-supplied credentials alone. Use middleware that validates tokens before any data resolution.',
  STRIP_COOKIES: 'Validate session tokens in HTTP cookies using server-side session stores. Do not rely solely on Authorization headers; protect cookie-based sessions with HttpOnly and Secure flags.',
  MUTATE_ID:     'Implement object-level authorisation (BOLA/IDOR) checks on every resolver. Verify the requesting user owns or has access to the requested resource ID.',
};

/** Escape HTML special characters */
function _esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Generates an executive-grade, self-contained HTML security audit report.
 * Includes: summary stats, CVSS scores, finding details with diff tables,
 * cURL reproduction commands, attack job summary, and remediation advice.
 * The output is a single HTML file with embedded CSS — no external dependencies.
 */
export function exportHtmlAuditReport(
  findings:   Finding[],
  attackJobs: AttackJob[] = [],
): string {
  const now    = new Date().toISOString();
  const vulns  = findings.filter(f => f.result.verdict === 'VULNERABLE').length;
  const inconc = findings.filter(f => f.result.verdict === 'INCONCLUSIVE').length;
  const safe   = findings.filter(f => f.result.verdict === 'PROTECTED').length;
  const totalHits = attackJobs.reduce((n, j) => n + j.payloads.filter(p => p.outcome === 'HIT').length, 0);

  const sorted = [...findings].sort((a, b) => b.severityScore - a.severityScore);

  // ── Finding cards ──────────────────────────────────────────────────────────
  const findingCardsHtml = sorted.map((f, i) => {
    const res    = f.result;
    const cvss   = CVSS_MAP[res.verdict] ?? CVSS_MAP['INCONCLUSIVE'];
    const remedy = REMEDIATION[res.testType] ?? 'Implement proper server-side authorisation controls.';
    const leakedHtml = res.diff.leakedFields.length > 0
      ? res.diff.leakedFields.map(field => `<span class="chip">${_esc(field)}</span>`).join(' ')
      : '<span style="color:#585b70">None detected</span>';

    const diffRowsHtml = res.diff.entries
      .filter(e => e.changed)
      .slice(0, 8)
      .map(e => `
        <tr>
          <td class="mono">${_esc(e.path)}</td>
          <td class="mono orig">${_esc(String(e.originalValue ?? 'null'))}</td>
          <td class="mono repl">${_esc(String(e.replayedValue ?? 'null'))}</td>
        </tr>`).join('');

    return `
    <div class="finding-card">
      <div class="finding-header">
        <div class="finding-num">#${i + 1}</div>
        <div class="finding-title">${_esc(f.operationName)}</div>
        <div class="cvss-badge" style="background:${cvss.color};color:#1e1e2e">
          CVSS ${cvss.score} &middot; ${cvss.rating}
        </div>
        <div class="verdict-pill verdict-${res.verdict.toLowerCase()}">${res.verdict}</div>
      </div>

      <table class="meta-table">
        <tr><th>Endpoint</th><td class="mono">${_esc(f.requestUrl)}</td></tr>
        <tr><th>Operation</th><td class="mono">${_esc(f.operationName)}</td></tr>
        <tr><th>Test Type</th><td>${_esc(res.testType)}</td></tr>
        <tr><th>HTTP Status</th><td>${res.replayedStatus}</td></tr>
        <tr><th>Duration</th><td>${res.replayedDurationMs}ms</td></tr>
        <tr><th>Tested At</th><td>${new Date(res.testedAt).toISOString()}</td></tr>
      </table>

      <div class="section-label">Evidence</div>
      <div class="evidence-box">${_esc(res.evidence)}</div>

      <div class="section-label">Leaked Fields (${res.diff.leakedFields.length})</div>
      <div class="chips">${leakedHtml}</div>

      ${diffRowsHtml ? `
      <div class="section-label">Response Diff</div>
      <table class="diff-table">
        <thead><tr><th>Path</th><th>Original</th><th>Replayed</th></tr></thead>
        <tbody>${diffRowsHtml}</tbody>
      </table>` : ''}

      <div class="section-label">Reproduction (cURL)</div>
      <pre class="curl-block">${_esc(f.curl)}</pre>

      <div class="section-label">Remediation</div>
      <div class="remedy-box">${_esc(remedy)}</div>
    </div>`;
  }).join('\n');

  // ── Attack job summary table ───────────────────────────────────────────────
  const attackRowsHtml = attackJobs.slice(0, 30).map(job => {
    const hits = job.payloads.filter(p => p.outcome === 'HIT').length;
    return `<tr>
      <td>${_esc(job.attackType)}</td>
      <td class="mono" style="font-size:11px">${_esc(job.requestUrl.slice(0, 60))}</td>
      <td><span class="status-${job.status.toLowerCase()}">${job.status}</span></td>
      <td>${job.payloads.length}</td>
      <td style="color:${hits > 0 ? '#f38ba8' : '#a6e3a1'}">${hits}</td>
    </tr>`;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>GraphQL Hunter — Security Audit Report</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',system-ui,sans-serif;background:#1e1e2e;color:#cdd6f4;line-height:1.5}
    a{color:#89b4fa}
    .page{max-width:1100px;margin:0 auto;padding:40px 24px}
    /* Header */
    .report-header{border-bottom:2px solid #313244;padding-bottom:24px;margin-bottom:32px}
    .report-title{font-size:28px;font-weight:700;color:#cba6f7;margin-bottom:6px}
    .report-meta{font-size:12px;color:#585b70}
    /* Summary pills */
    .summary-bar{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px}
    .pill{background:#181825;border:1px solid #313244;border-radius:8px;padding:14px 20px;flex:1;min-width:140px;text-align:center}
    .pill .num{font-size:32px;font-weight:700;display:block;margin-bottom:2px}
    .pill .lbl{font-size:11px;color:#585b70;text-transform:uppercase;letter-spacing:.05em}
    .num.vuln{color:#f38ba8} .num.inconc{color:#fab387} .num.safe{color:#a6e3a1} .num.atk{color:#89dceb}
    /* Section */
    .section-h2{font-size:18px;font-weight:600;color:#89b4fa;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #313244}
    /* Finding card */
    .finding-card{background:#181825;border:1px solid #313244;border-radius:10px;padding:20px;margin-bottom:20px}
    .finding-header{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px}
    .finding-num{background:#313244;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:600;color:#7f849c}
    .finding-title{font-size:15px;font-weight:600;flex:1;color:#cdd6f4}
    .cvss-badge{border-radius:5px;padding:2px 10px;font-size:11px;font-weight:700}
    .verdict-pill{border-radius:4px;padding:2px 10px;font-size:11px;font-weight:700}
    .verdict-vulnerable{background:#45182220;color:#f38ba8;border:1px solid #f38ba840}
    .verdict-inconclusive{background:#45332220;color:#fab387;border:1px solid #fab38740}
    .verdict-protected{background:#1e3a2220;color:#a6e3a1;border:1px solid #a6e3a140}
    /* Tables */
    .meta-table{width:100%;font-size:12px;border-collapse:collapse;margin-bottom:12px}
    .meta-table th{text-align:left;color:#7f849c;padding:3px 6px;width:120px;font-weight:500}
    .meta-table td{padding:3px 6px;color:#cdd6f4}
    .diff-table{width:100%;font-size:11px;border-collapse:collapse;margin-bottom:12px}
    .diff-table th{background:#313244;color:#7f849c;padding:4px 8px;text-align:left}
    .diff-table td{padding:3px 8px;border-top:1px solid #1e1e2e}
    .diff-table .orig{color:#f38ba8} .diff-table .repl{color:#a6e3a1}
    /* Labels & boxes */
    .section-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#585b70;margin:12px 0 6px}
    .evidence-box{background:#11111b;border-left:3px solid #89b4fa;padding:10px 14px;font-size:12px;border-radius:0 6px 6px 0;margin-bottom:4px;color:#a6adc8;font-family:monospace}
    .remedy-box{background:#11111b;border-left:3px solid #a6e3a1;padding:10px 14px;font-size:12px;border-radius:0 6px 6px 0;color:#a6adc8}
    .curl-block{background:#11111b;border:1px solid #313244;border-radius:6px;padding:10px 14px;font-size:11px;font-family:monospace;color:#a6e3a1;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin-bottom:4px}
    .chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px}
    .chip{background:#313244;border-radius:4px;padding:2px 8px;font-size:11px;font-family:monospace;color:#89b4fa}
    .mono{font-family:monospace;font-size:11px}
    /* Attack table */
    .attack-table{width:100%;border-collapse:collapse;font-size:12px}
    .attack-table th{background:#313244;padding:6px 10px;text-align:left;font-weight:500;color:#7f849c}
    .attack-table td{padding:5px 10px;border-top:1px solid #1e1e2e}
    .status-success{color:#a6e3a1} .status-error{color:#f38ba8} .status-partial{color:#fab387} .status-running{color:#89b4fa}
    /* Footer */
    .report-footer{margin-top:48px;padding-top:16px;border-top:1px solid #313244;font-size:11px;color:#45475a;text-align:center}
  </style>
</head>
<body>
<div class="page">

  <div class="report-header">
    <div class="report-title">🎯 GraphQL Hunter — Security Audit Report</div>
    <div class="report-meta">Generated: ${now} &nbsp;|&nbsp; Tool: GraphQL Hunter v0.1.0</div>
  </div>

  <!-- Summary -->
  <div class="summary-bar">
    <div class="pill"><span class="num vuln">${vulns}</span><span class="lbl">Vulnerable</span></div>
    <div class="pill"><span class="num inconc">${inconc}</span><span class="lbl">Inconclusive</span></div>
    <div class="pill"><span class="num safe">${safe}</span><span class="lbl">Protected</span></div>
    <div class="pill"><span class="num atk">${attackJobs.length}</span><span class="lbl">Attack Jobs</span></div>
    <div class="pill"><span class="num" style="color:#cba6f7">${totalHits}</span><span class="lbl">Attack Hits</span></div>
    <div class="pill"><span class="num" style="color:#cdd6f4">${findings.length}</span><span class="lbl">Total Findings</span></div>
  </div>

  <!-- Findings -->
  <div class="section-h2">Authorization Test Findings</div>
  ${findings.length === 0
    ? '<p style="color:#585b70;font-size:13px">No authorization findings recorded.</p>'
    : findingCardsHtml
  }

  <!-- Attack Jobs -->
  ${attackJobs.length > 0 ? `
  <div class="section-h2">Active Attack Job Summary</div>
  <table class="attack-table">
    <thead><tr>
      <th>Attack Type</th><th>Target</th><th>Status</th><th>Payloads</th><th>Hits</th>
    </tr></thead>
    <tbody>${attackRowsHtml}</tbody>
  </table>` : ''}

  <div class="report-footer">
    Generated by <strong>GraphQL Hunter</strong> — GraphQL Security Auditing Extension &nbsp;|&nbsp;
    This report is intended for authorised security professionals only.
  </div>

</div>
</body>
</html>`;
}
