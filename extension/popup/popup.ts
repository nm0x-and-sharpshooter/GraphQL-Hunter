// ─────────────────────────────────────────────────────────────────────────────
// popup.ts — Popup UI controller
//
// Responsibilities:
//   - Load and display captured requests from background storage
//   - Render live feed updates pushed from background via runtime.onMessage
//   - Render aggregate stats including detected risks
//   - Render risk badges and field counts per captured query
//   - Clear button handling
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import type { CapturedRequest, GraphQLRequestBody, HunterStats } from '../types/graphql';
import type { HunterMessage } from '../types/messages';

// ── DOM refs ──────────────────────────────────────────────────────────────────

const elTotal     = document.getElementById('stat-total')!;
const elEndpoints = document.getElementById('stat-endpoints')!;
const elMutations = document.getElementById('stat-mutations')!;
const elBatch     = document.getElementById('stat-batch')!;
const elRisks     = document.getElementById('stat-risks')!;
const elFeed      = document.getElementById('feed')!;
const elEmpty     = document.getElementById('empty-state')!;
const btnClear    = document.getElementById('btn-clear')!;
const btnDash     = document.getElementById('btn-dashboard')!;

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
    </div>
    ${riskBadgeHtml}
    <span class="item-status ${statusClass}">${statusText}</span>
    <span class="item-duration">${duration != null ? fmtMs(duration) : ''}</span>
  `;
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

// ── Data loading ──────────────────────────────────────────────────────────────

async function refresh(): Promise<void> {
  const [requests, stats] = await Promise.all([
    browser.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS' }) as Promise<CapturedRequest[]>,
    browser.runtime.sendMessage({ type: 'GET_STATS' })              as Promise<HunterStats>,
  ]);
  renderFeed(requests  ?? []);
  renderStats(stats    ?? { totalRequests: 0, endpoints: [], batchCount: 0, mutationCount: 0, queryCount: 0, riskCount: 0 });
}

// ── Live updates from background ──────────────────────────────────────────────

browser.runtime.onMessage.addListener((raw: unknown) => {
  const msg = raw as HunterMessage;
  if (msg.type === 'GRAPHQL_REQUEST_CAPTURED') {
    // Cheapest update: just re-render (storage has already been written)
    refresh();
  }
});

// ── Event listeners ───────────────────────────────────────────────────────────

btnClear.addEventListener('click', async () => {
  await browser.runtime.sendMessage({ type: 'CLEAR_REQUESTS' });
  await refresh();
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
