// ─────────────────────────────────────────────────────────────────────────────
// popup.ts — Popup UI controller
//
// Responsibilities:
//   - Load and display captured requests from background storage
//   - Render live feed updates pushed from background via runtime.onMessage
//   - Render aggregate stats including detected risks
//   - Render risk badges, complexity scores, and field counts per captured query
//   - Day 4: Trigger authorization tests (NO_AUTH, STRIP_COOKIES, MUTATE_ID)
//   - Day 4: Render active auth findings, response diffs, and export reports
//   - Clear button handling & tab switching
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import type {
  CapturedRequest,
  GraphQLRequestBody,
  HunterStats,
  SchemaModel,
  AuthTestType,
  AuthTestResult,
} from '../types/graphql';
import type { HunterMessage } from '../types/messages';

// ── DOM refs ──────────────────────────────────────────────────────────────────

const elTotal         = document.getElementById('stat-total')!;
const elEndpoints     = document.getElementById('stat-endpoints')!;
const elMutations     = document.getElementById('stat-mutations')!;
const elBatch         = document.getElementById('stat-batch')!;
const elRisks         = document.getElementById('stat-risks')!;
const elFeed          = document.getElementById('feed')!;
const elEmpty         = document.getElementById('empty-state')!;
const btnClear        = document.getElementById('btn-clear')!;
const btnDash         = document.getElementById('btn-dashboard')!;

// ── Day 3: Tab + Schema DOM refs ──────────────────────────────────────────────
const btnTabTraffic   = document.getElementById('tab-traffic')!;
const btnTabSchema    = document.getElementById('tab-schema')!;
const panelTraffic    = document.getElementById('panel-traffic')!;
const panelSchema     = document.getElementById('panel-schema')!;
const elSchemaEmpty   = document.getElementById('schema-empty')!;
const elSchemaStats   = document.getElementById('schema-stats')!;
const elSchemaTree    = document.getElementById('schema-tree')!;
const elSchemaEps     = document.getElementById('schema-endpoints')!;
const elEndpointList  = document.getElementById('endpoint-list')!;
const elSchemaStatTypes    = document.getElementById('schema-stat-types')!;
const elSchemaStatFields   = document.getElementById('schema-stat-fields')!;
const elSchemaStatEndpoints = document.getElementById('schema-stat-endpoints')!;
const elSchemaTypeCount    = document.getElementById('schema-type-count')!;
const btnClearSchema  = document.getElementById('btn-clear-schema')!;

// ── Day 4: Findings / Auth Tests DOM refs ─────────────────────────────────────
const btnTabFindings    = document.getElementById('tab-findings')!;
const panelFindings     = document.getElementById('panel-findings')!;
const elFindingsCount   = document.getElementById('findings-count')!;
const elFindingsEmpty   = document.getElementById('findings-empty')!;
const elFindingsList    = document.getElementById('findings-list')!;
const btnExportFindings = document.getElementById('btn-export-findings')!;

// ── State ─────────────────────────────────────────────────────────────────────

let currentRequests: CapturedRequest[] = [];
const pendingTests = new Set<string>();

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Escape user-supplied strings for safe innerHTML injection. */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Infer operation type from query string. */
function inferType(query: string): 'query' | 'mutation' | 'sub' {
  const t = query.trim().toLowerCase();
  if (t.startsWith('mutation'))     return 'mutation';
  if (t.startsWith('subscription')) return 'sub';
  return 'query';
}

/** Infer operation name from query string (regex fallback). */
function inferName(query: string): string {
  const m = query.match(/(?:query|mutation|subscription)\s+(\w+)/i);
  return m?.[1] ?? 'anonymous';
}

/** Format a duration in ms to a human-readable string. */
function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/** Extract a short pathname for display. */
function fmtUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname;
  } catch {
    return url.slice(0, 40);
  }
}

/** Helper to check for empty/null-like values in response diffs. */
function isNullLike(v: unknown): boolean {
  if (v === null || v === undefined) return true;
  if (Array.isArray(v) && v.length === 0) return true;
  if (typeof v === 'object' && v !== null && Object.keys(v as object).length === 0) return true;
  return false;
}

// ── Day 4: Auth test trigger ──────────────────────────────────────────────────

async function triggerAuthTest(req: CapturedRequest, testType: AuthTestType = 'NO_AUTH'): Promise<void> {
  if (pendingTests.has(req.id)) return;
  pendingTests.add(req.id);
  renderFeed(currentRequests);

  try {
    const result = await browser.runtime.sendMessage({
      type: 'RUN_AUTH_TEST',
      payload: { requestId: req.id, testType },
    }) as AuthTestResult;

    if (result && !('error' in result)) {
      req.authTests = [...(req.authTests ?? []), result];
    }
  } catch (err) {
    console.error('[GraphQL Hunter] Auth test failed:', err);
  } finally {
    pendingTests.delete(req.id);
    await refresh();
  }
}

// ── Feed rendering ────────────────────────────────────────────────────────────

function buildFeedItem(req: CapturedRequest): HTMLElement {
  const bodies: GraphQLRequestBody[] = Array.isArray(req.body)
    ? req.body
    : [req.body];

  const primaryBody = bodies[0];
  const primaryOp   = req.analysis?.operations[0];

  // Derive operation type & name (prefer AST analysis, fallback to regex)
  const opType = (primaryOp && primaryOp.operationType !== 'unknown')
    ? (primaryOp.operationType === 'subscription' ? 'sub' : primaryOp.operationType)
    : inferType(primaryBody.query);

  const opName = (primaryOp && primaryOp.operationName !== 'anonymous')
    ? primaryOp.operationName
    : primaryBody.operationName ?? inferName(primaryBody.query);

  const isBatch    = req.isBatch;
  const statusCode = req.response?.status;
  const duration   = req.response?.durationMs;

  const badgeClass = isBatch ? 'batch' : opType;
  const badgeLabel = isBatch
    ? `B${bodies.length}`
    : opType === 'mutation' ? 'MUT'
    : opType === 'sub'      ? 'SUB'
    : 'QRY';

  const statusClass = statusCode == null ? 'pending'
                    : statusCode < 400   ? 'ok'
                    : 'err';
  const statusText  = statusCode?.toString() ?? '…';

  // Day 2: Risk badge and field count
  const totalFields = req.analysis?.operations.reduce((n, o) => n + o.fieldCount, 0);
  const riskLevel   = req.analysis?.overallRisk ?? 'INFO';
  const riskClass   = riskLevel.toLowerCase();

  const topFinding = primaryOp?.findings.find(f => f.level === riskLevel) ?? primaryOp?.findings[0];
  const tooltipText = topFinding
    ? `${topFinding.title}: ${topFinding.detail}`
    : `Risk level: ${riskLevel}`;

  const riskBadgeHtml = req.analysis
    ? `<span class="risk-badge ${riskClass}" title="${escapeHtml(tooltipText)}">${riskLevel}</span>`
    : '';

  const fieldCountHtml = (totalFields != null && totalFields > 0)
    ? `<span class="item-field-count">${totalFields} ${totalFields === 1 ? 'field' : 'fields'}</span><span class="item-meta-divider">·</span>`
    : '';

  // Day 3: Complexity badge
  const complexity       = primaryOp?.complexity;
  const complexityHtml   = complexity && complexity.depth > 2
    ? `<span class="complexity-badge ${complexity.isHighComplexity ? 'high' : ''}" title="Depth: ${complexity.depth} | Cost: ${complexity.estimatedCost}">d${complexity.depth}</span>`
    : '';

  // Day 4: Latest verdict badge
  const latestAuthTest = req.authTests && req.authTests.length > 0
    ? req.authTests[req.authTests.length - 1]
    : null;
  const verdictBadgeHtml = latestAuthTest
    ? `<span class="verdict-badge ${latestAuthTest.verdict}" title="${escapeHtml(latestAuthTest.evidence)}">${latestAuthTest.verdict}</span>`
    : '';

  // Day 4: Auth test control or spinner
  let authControlHtml = '';
  if (pendingTests.has(req.id)) {
    authControlHtml = `
      <div class="auth-spinner">
        <div class="auth-spinner-ring"></div>
        <span>Testing auth…</span>
      </div>`;
  } else {
    authControlHtml = `
      <div class="auth-test-wrap">
        <button class="btn-auth-test" type="button" data-action="run-default" title="Replay request with stripped auth">
          <svg viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path d="M8 1a3 3 0 00-3 3v2H4a1 1 0 00-1 1v7a1 1 0 001 1h8a1 1 0 001-1V7a1 1 0 00-1-1h-1V4a3 3 0 00-3-3zm1 5H7V4a1 1 0 012 0v2z" fill="currentColor"/>
          </svg>
          Test Auth
        </button>
        <button class="btn-auth-caret" type="button" data-action="toggle-menu" title="Choose auth test strategy">
          <svg viewBox="0 0 10 10" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path d="M2.5 4l2.5 2.5L7.5 4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
          </svg>
        </button>
        <div class="auth-test-menu hidden" id="menu-${req.id}">
          <button class="auth-menu-item" type="button" data-strategy="NO_AUTH">
            <strong>No Auth</strong>
            <span>Strip Auth header & cookies</span>
          </button>
          <div class="auth-menu-divider"></div>
          <button class="auth-menu-item" type="button" data-strategy="STRIP_COOKIES">
            <strong>Strip Cookies</strong>
            <span>Keep Authorization header</span>
          </button>
          <div class="auth-menu-divider"></div>
          <button class="auth-menu-item" type="button" data-strategy="MUTATE_ID">
            <strong>Mutate IDs</strong>
            <span>Test BOLA / IDOR with ID ±1</span>
          </button>
        </div>
      </div>`;
  }

  const item     = document.createElement('div');
  item.className = 'feed-item';
  item.setAttribute('role', 'listitem');
  item.innerHTML = `
    <div class="op-badge ${badgeClass}" title="${opType}">${badgeLabel}</div>
    <div class="item-body">
      <span class="item-op-name">${escapeHtml(opName)}</span>
      <div class="item-meta-row">
        ${fieldCountHtml}
        <span class="item-url">${escapeHtml(fmtUrl(req.url))}</span>
      </div>
      ${authControlHtml}
    </div>
    ${verdictBadgeHtml}
    ${complexityHtml}
    ${riskBadgeHtml}
    <span class="item-status ${statusClass}">${statusText}</span>
    <span class="item-duration">${duration != null ? fmtMs(duration) : ''}</span>
  `;

  // Attach auth button event listeners
  const btnRun = item.querySelector<HTMLButtonElement>('[data-action="run-default"]');
  if (btnRun) {
    btnRun.addEventListener('click', (e) => {
      e.stopPropagation();
      triggerAuthTest(req, 'NO_AUTH');
    });
  }

  const btnCaret = item.querySelector<HTMLButtonElement>('[data-action="toggle-menu"]');
  const menu     = item.querySelector<HTMLElement>(`#menu-${req.id}`);
  if (btnCaret && menu) {
    btnCaret.addEventListener('click', (e) => {
      e.stopPropagation();
      document.querySelectorAll('.auth-test-menu:not(.hidden)').forEach(m => {
        if (m !== menu) m.classList.add('hidden');
      });
      menu.classList.toggle('hidden');
    });
  }

  const menuItems = item.querySelectorAll<HTMLButtonElement>('.auth-menu-item');
  menuItems.forEach(mi => {
    mi.addEventListener('click', (e) => {
      e.stopPropagation();
      if (menu) menu.classList.add('hidden');
      const strategy = mi.getAttribute('data-strategy') as AuthTestType;
      triggerAuthTest(req, strategy);
    });
  });

  return item;
}

function renderFeed(requests: CapturedRequest[]): void {
  // Clear existing items (keep empty-state placeholder in DOM)
  const existingItems = elFeed.querySelectorAll('.feed-item');
  existingItems.forEach(el => el.remove());

  if (requests.length === 0) {
    elEmpty.style.display = '';
    return;
  }

  elEmpty.style.display = 'none';

  // Show newest 20
  for (const req of requests.slice(0, 20)) {
    elFeed.appendChild(buildFeedItem(req));
  }
}

function renderStats(stats: HunterStats): void {
  elTotal.textContent     = String(stats.totalRequests);
  elEndpoints.textContent = String(stats.endpoints.length);
  elMutations.textContent = String(stats.mutationCount);
  elBatch.textContent     = String(stats.batchCount);
  if (elRisks) {
    elRisks.textContent   = String(stats.riskCount ?? 0);
  }
}

// ── Day 3: Schema rendering ───────────────────────────────────────────────────

function renderSchema(model: SchemaModel): void {
  const typeNames  = Object.keys(model.types);
  const totalTypes = typeNames.length;
  const totalFields = typeNames.reduce(
    (n, t) => n + Object.keys(model.types[t].fields).length, 0,
  );

  // Update tab badge
  elSchemaTypeCount.textContent = String(totalTypes);

  if (totalTypes === 0) {
    elSchemaEmpty.style.display  = '';
    elSchemaStats.style.display  = 'none';
    elSchemaTree.innerHTML       = '';
    elSchemaEps.style.display    = 'none';
    return;
  }

  // Stats bar
  elSchemaEmpty.style.display       = 'none';
  elSchemaStats.style.display       = '';
  elSchemaStatTypes.textContent     = String(totalTypes);
  elSchemaStatFields.textContent    = String(totalFields);
  elSchemaStatEndpoints.textContent = String(model.endpoints.length);

  // Type tree
  elSchemaTree.innerHTML = '';
  for (const typeName of typeNames.sort()) {
    const schemaType = model.types[typeName];
    const fieldNames = Object.keys(schemaType.fields);

    const node = document.createElement('div');
    node.className = 'schema-type-node';

    node.innerHTML = `
      <div class="schema-type-header" role="button" tabindex="0" aria-expanded="false">
        <svg class="schema-chevron" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <path d="M4 2l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span class="schema-type-name">${escapeHtml(typeName)}</span>
        <span class="schema-type-count">${fieldNames.length} ${fieldNames.length === 1 ? 'field' : 'fields'}</span>
      </div>
      <div class="schema-field-list" role="list">
        ${fieldNames.sort().map(fn => {
          const f = schemaType.fields[fn];
          const argsText = f.args.length > 0 ? `(${f.args.join(', ')})` : '';
          const opPills  = f.seenInOps
            .map(op => `<span class="schema-op-pill ${op}">${op === 'subscription' ? 'sub' : op}</span>`)
            .join('');
          return `
            <div class="schema-field-row" role="listitem">
              <span class="schema-field-name">${escapeHtml(fn)}</span>
              ${argsText ? `<span class="schema-field-args">${escapeHtml(argsText)}</span>` : ''}
              <span class="schema-field-ops">${opPills}</span>
              <span class="schema-field-count" title="${f.observationCount} observations">×${f.observationCount}</span>
            </div>`;
        }).join('')}
      </div>
    `;

    // Toggle open/close on header click
    const header = node.querySelector('.schema-type-header')!;
    header.addEventListener('click', () => {
      node.classList.toggle('open');
      header.setAttribute('aria-expanded', String(node.classList.contains('open')));
    });
    header.addEventListener('keydown', (e) => {
      if ((e as KeyboardEvent).key === 'Enter' || (e as KeyboardEvent).key === ' ') {
        (header as HTMLElement).click();
      }
    });

    elSchemaTree.appendChild(node);
  }

  // Endpoints
  if (model.endpoints.length > 0) {
    elSchemaEps.style.display = '';
    elEndpointList.innerHTML  = model.endpoints
      .map(ep => `<li class="endpoint-item">${escapeHtml(ep)}</li>`)
      .join('');
  } else {
    elSchemaEps.style.display = 'none';
  }
}

// ── Day 4: Findings rendering ─────────────────────────────────────────────────

function renderFindings(requests: CapturedRequest[]): void {
  const findings: { req: CapturedRequest; test: AuthTestResult }[] = [];
  for (const req of requests) {
    if (req.authTests && req.authTests.length > 0) {
      for (const test of req.authTests) {
        findings.push({ req, test });
      }
    }
  }

  // Sort descending by testedAt
  findings.sort((a, b) => b.test.testedAt - a.test.testedAt);

  // Update badge count (prioritize vulnerable count if any)
  const vulnCount = findings.filter(f => f.test.verdict === 'VULNERABLE').length;
  elFindingsCount.textContent = String(vulnCount > 0 ? vulnCount : findings.length);

  elFindingsList.innerHTML = '';

  if (findings.length === 0) {
    elFindingsEmpty.style.display = '';
    return;
  }

  elFindingsEmpty.style.display = 'none';

  for (const { req, test } of findings) {
    const bodies = Array.isArray(req.body) ? req.body : [req.body];
    const opName = req.analysis?.operations[0]?.operationName ?? inferName(bodies[0]?.query ?? '');

    const card = document.createElement('div');
    card.className = `finding-card ${test.verdict}`;

    // Leaked fields chips
    const leakedListHtml = test.diff.leakedFields.length > 0
      ? `<div class="finding-leaked-list">
          ${test.diff.leakedFields.slice(0, 8).map(f => `<span class="finding-leaked-chip">${escapeHtml(f)}</span>`).join('')}
          ${test.diff.leakedFields.length > 8 ? `<span class="finding-leaked-chip">+${test.diff.leakedFields.length - 8} more</span>` : ''}
        </div>`
      : '';

    // Diff view (display changed / non-empty fields)
    const displayEntries = test.diff.entries
      .filter(e => e.changed || !isNullLike(e.replayedValue))
      .slice(0, 6);

    const diffViewHtml = displayEntries.length > 0
      ? `<div class="diff-view">
          <div class="diff-header">
            <span>Response Diff (${test.diff.entries.filter(e => e.changed).length} changed)</span>
            <span>HTTP ${test.replayedStatus}</span>
          </div>
          ${displayEntries.map(e => `
            <div class="diff-row">
              <div class="diff-cell ${e.changed ? 'changed' : ''}" title="${escapeHtml(String(e.originalValue ?? 'null'))}">
                <span class="diff-label">orig</span>${escapeHtml(String(e.originalValue ?? 'null'))}
              </div>
              <div class="diff-cell ${!isNullLike(e.replayedValue) ? 'leaked' : ''}" title="${escapeHtml(String(e.replayedValue ?? 'null'))}">
                <span class="diff-label">${escapeHtml(e.path)}</span>${escapeHtml(String(e.replayedValue ?? 'null'))}
              </div>
            </div>
          `).join('')}
        </div>`
      : '';

    card.innerHTML = `
      <div class="finding-card-header">
        <span class="finding-op-name">${escapeHtml(opName)}</span>
        <span class="verdict-badge ${test.verdict}">${test.verdict}</span>
        <span class="finding-test-type">${test.testType}</span>
        <span class="finding-timestamp">${new Date(test.testedAt).toLocaleTimeString()} · ${fmtMs(test.replayedDurationMs)} · HTTP ${test.replayedStatus}</span>
      </div>
      <div class="finding-evidence">${escapeHtml(test.evidence)}</div>
      ${leakedListHtml}
      ${diffViewHtml}
    `;

    elFindingsList.appendChild(card);
  }
}

// ── Data loading ──────────────────────────────────────────────────────────────

async function refresh(): Promise<void> {
  const [requests, stats, schema] = await Promise.all([
    browser.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS' }) as Promise<CapturedRequest[]>,
    browser.runtime.sendMessage({ type: 'GET_STATS' })              as Promise<HunterStats>,
    browser.runtime.sendMessage({ type: 'GET_SCHEMA' })             as Promise<SchemaModel>,
  ]);
  currentRequests = requests ?? [];
  renderFeed(currentRequests);
  renderStats(stats ?? { totalRequests: 0, endpoints: [], batchCount: 0, mutationCount: 0, queryCount: 0, riskCount: 0 });
  renderSchema(schema ?? { types: {}, endpoints: [], lastUpdated: 0 });
  renderFindings(currentRequests);
}

// ── Live updates from background ──────────────────────────────────────────────

browser.runtime.onMessage.addListener((raw: unknown) => {
  const msg = raw as HunterMessage;
  if (msg.type === 'GRAPHQL_REQUEST_CAPTURED' || msg.type === 'AUTH_TEST_RESULT') {
    refresh();
  }
});

// ── Event listeners ───────────────────────────────────────────────────────────

btnClear.addEventListener('click', async () => {
  await browser.runtime.sendMessage({ type: 'CLEAR_REQUESTS' });
  await refresh();
});

// Day 3: Schema clear
btnClearSchema.addEventListener('click', async () => {
  await browser.runtime.sendMessage({ type: 'CLEAR_SCHEMA' });
  await refresh();
});

// Day 4: Export findings
btnExportFindings.addEventListener('click', () => {
  const findings: { reqUrl: string; opName: string; timestamp: number; test: AuthTestResult }[] = [];
  for (const req of currentRequests) {
    if (req.authTests && req.authTests.length > 0) {
      const bodies = Array.isArray(req.body) ? req.body : [req.body];
      const opName = req.analysis?.operations[0]?.operationName ?? inferName(bodies[0]?.query ?? '');
      for (const test of req.authTests) {
        findings.push({
          reqUrl: req.url,
          opName,
          timestamp: req.timestamp,
          test,
        });
      }
    }
  }

  if (findings.length === 0) return;

  const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `graphql-hunter-auth-findings-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// Day 3 & Day 4: Tab switching
function switchTab(target: 'traffic' | 'schema' | 'findings'): void {
  btnTabTraffic.classList.toggle('active', target === 'traffic');
  btnTabTraffic.setAttribute('aria-selected', String(target === 'traffic'));
  btnTabSchema.classList.toggle('active', target === 'schema');
  btnTabSchema.setAttribute('aria-selected', String(target === 'schema'));
  btnTabFindings.classList.toggle('active', target === 'findings');
  btnTabFindings.setAttribute('aria-selected', String(target === 'findings'));

  panelTraffic.classList.toggle('hidden', target !== 'traffic');
  panelSchema.classList.toggle('hidden', target !== 'schema');
  panelFindings.classList.toggle('hidden', target !== 'findings');
}

btnTabTraffic.addEventListener('click',  () => switchTab('traffic'));
btnTabSchema.addEventListener('click',   () => switchTab('schema'));
btnTabFindings.addEventListener('click', () => switchTab('findings'));

// Global click listener to dismiss auth test dropdowns when clicking outside
document.addEventListener('click', (e) => {
  const target = e.target as HTMLElement;
  if (!target.closest('.auth-test-wrap')) {
    document.querySelectorAll('.auth-test-menu:not(.hidden)').forEach(m => m.classList.add('hidden'));
  }
});

btnDash.addEventListener('click', () => {
  // Day 9-10: open full dashboard tab
  browser.tabs.create({ url: browser.runtime.getURL('dashboard/dashboard.html') })
    .catch(() => {
      // Dashboard not built yet — show coming soon in console
      console.info('[GraphQL Hunter] Full dashboard coming soon (Day 9).');
    });
});

// ── Init ──────────────────────────────────────────────────────────────────────

refresh();
