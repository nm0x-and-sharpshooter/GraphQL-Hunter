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
import type { CapturedRequest, GraphQLRequestBody, HunterStats, SchemaModel } from '../types/graphql';
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
const btnClearSchema  = document.getElementById('btn-clear-schema')!;;

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

  // Day 3: Complexity badge
  const complexity       = primaryOp?.complexity;
  const complexityHtml   = complexity && complexity.depth > 2
    ? `<span class="complexity-badge ${complexity.isHighComplexity ? 'high' : ''}" title="Depth: ${complexity.depth} | Cost: ${complexity.estimatedCost}">d${complexity.depth}</span>`
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
    ${complexityHtml}
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

// ── Data loading ──────────────────────────────────────────────────────────────

async function refresh(): Promise<void> {
  const [requests, stats, schema] = await Promise.all([
    browser.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS' }) as Promise<CapturedRequest[]>,
    browser.runtime.sendMessage({ type: 'GET_STATS' })              as Promise<HunterStats>,
    browser.runtime.sendMessage({ type: 'GET_SCHEMA' })             as Promise<SchemaModel>,
  ]);
  renderFeed(requests   ?? []);
  renderStats(stats     ?? { totalRequests: 0, endpoints: [], batchCount: 0, mutationCount: 0, queryCount: 0, riskCount: 0 });
  renderSchema(schema   ?? { types: {}, endpoints: [], lastUpdated: 0 });
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

// Day 3: Schema clear
btnClearSchema.addEventListener('click', async () => {
  await browser.runtime.sendMessage({ type: 'CLEAR_SCHEMA' });
  await refresh();
});

// Day 3: Tab switching
function switchTab(target: 'traffic' | 'schema'): void {
  const isTraffic = target === 'traffic';
  btnTabTraffic.classList.toggle('active', isTraffic);
  btnTabTraffic.setAttribute('aria-selected', String(isTraffic));
  btnTabSchema.classList.toggle('active', !isTraffic);
  btnTabSchema.setAttribute('aria-selected', String(!isTraffic));
  panelTraffic.classList.toggle('hidden', !isTraffic);
  panelSchema.classList.toggle('hidden', isTraffic);
}

btnTabTraffic.addEventListener('click', () => switchTab('traffic'));
btnTabSchema.addEventListener('click',  () => switchTab('schema'));

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
