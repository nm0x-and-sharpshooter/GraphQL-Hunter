// ─────────────────────────────────────────────────────────────────────────────
// dashboard.ts — Full Dashboard Controller (Day 5)
//
// Responsibilities:
//   - Load findings, requests, stats, schema from background on open
//   - Render Overview section (stats cards, donut chart, endpoint list)
//   - Render Findings section (filterable/sortable table)
//   - Render Traffic section (read-only captured requests feed)
//   - Render Schema section (collapsible type tree)
//   - Open/close Finding Detail Drawer on row click
//   - Drawer: show diff table, evidence, curl, analyst note (auto-save on blur)
//   - Export Markdown and JSON reports via blob download
//   - Listen for AUTH_TEST_RESULT broadcast to refresh live
//   - Sidebar navigation with active-state management
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import type {
  CapturedRequest,
  HunterStats,
  SchemaModel,
  Finding,
  AuthVerdict,
  GraphQLRequestBody,
} from '../types/graphql';
import type { HunterMessage } from '../types/messages';
import { generateMarkdownReport, generateJsonReport } from '../analysis/evidence-utils';

// ── DOM refs ──────────────────────────────────────────────────────────────────

// Header stats
const elHstatTotal  = document.getElementById('hstat-total')!;
const elHstatVuln   = document.getElementById('hstat-vuln')!;
const elHstatInconc = document.getElementById('hstat-inconc')!;
const elHstatSafe   = document.getElementById('hstat-safe')!;

// Overview
const elOvVuln     = document.getElementById('ov-vuln')!;
const elOvInconc   = document.getElementById('ov-inconc')!;
const elOvSafe     = document.getElementById('ov-safe')!;
const elOvTotal    = document.getElementById('ov-total')!;
const elOvEndpoints = document.getElementById('ov-endpoints')!;
const elOvEpList   = document.getElementById('ov-endpoint-list')!;
const elDonutChart  = document.getElementById('donut-chart')!;
const elDonutVuln  = document.getElementById('donut-label-vuln')!;
const elDonutInconc = document.getElementById('donut-label-inconc')!;
const elDonutSafe  = document.getElementById('donut-label-safe')!;

// Findings
const elFindingsEmpty = document.getElementById('findings-empty-state')!;
const elFindingsTable = document.getElementById('findings-table')!;
const elFindingsTbody = document.getElementById('findings-tbody')!;
const elNavFindingsCount = document.getElementById('nav-findings-count')!;
const elNavTrafficCount  = document.getElementById('nav-traffic-count')!;
const elNavSchemaCount   = document.getElementById('nav-schema-count')!;

// Traffic
const elTrafficFeed  = document.getElementById('traffic-feed')!;
const elTrafficEmpty = document.getElementById('traffic-empty-state')!;

// Schema
const elSchemaTreeDash  = document.getElementById('schema-tree-dash')!;
const elSchemaEmptyDash = document.getElementById('schema-empty-state')!;
const elSchemaFieldSummary = document.getElementById('schema-field-summary')!;

// Drawer
const elDrawerOverlay   = document.getElementById('drawer-overlay')!;
const elDrawer          = document.getElementById('detail-drawer')!;
const elDrawerOpName    = document.getElementById('drawer-op-name')!;
const elDrawerBadge     = document.getElementById('drawer-verdict-badge')!;
const elDrawerBody      = document.getElementById('drawer-body')!;
const btnDrawerClose    = document.getElementById('btn-drawer-close')!;

// Buttons
const btnExportMd    = document.getElementById('btn-export-md')!;
const btnExportJson  = document.getElementById('btn-export-json')!;
const btnClearFindings = document.getElementById('btn-clear-findings')!;

// ── State ─────────────────────────────────────────────────────────────────────

let allFindings:  Finding[]         = [];
let allRequests:  CapturedRequest[] = [];
let currentStats: HunterStats | null = null;
let currentSchema: SchemaModel | null = null;

let activeFilter: 'all' | AuthVerdict = 'all';
let activeSort:   'severity' | 'recency' = 'severity';
let activeSection = 'overview';

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname + u.pathname;
  } catch {
    return url.slice(0, 50);
  }
}

function fmtMs(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

function fmtTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function isNullLike(v: unknown): boolean {
  if (v === null || v === undefined) return true;
  if (Array.isArray(v) && v.length === 0) return true;
  if (typeof v === 'object' && v !== null && Object.keys(v as object).length === 0) return true;
  return false;
}

function inferOpName(req: CapturedRequest): string {
  const bodies: GraphQLRequestBody[] = Array.isArray(req.body) ? req.body : [req.body];
  const fromAnalysis = req.analysis?.operations[0]?.operationName;
  if (fromAnalysis && fromAnalysis !== 'anonymous') return fromAnalysis;
  const m = bodies[0]?.query?.match(/(?:query|mutation|subscription)\s+(\w+)/i);
  return m?.[1] ?? 'anonymous';
}

function inferOpType(req: CapturedRequest): string {
  const primary = req.analysis?.operations[0];
  if (primary && primary.operationType !== 'unknown') {
    return primary.operationType === 'subscription' ? 'sub' : primary.operationType;
  }
  const q = (Array.isArray(req.body) ? req.body[0] : req.body)?.query ?? '';
  const t = q.trim().toLowerCase();
  if (t.startsWith('mutation')) return 'mutation';
  if (t.startsWith('subscription')) return 'sub';
  return 'query';
}

function downloadBlob(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Sidebar navigation ────────────────────────────────────────────────────────

function switchSection(section: string): void {
  activeSection = section;

  document.querySelectorAll<HTMLButtonElement>('.nav-item').forEach(btn => {
    const isActive = btn.dataset['section'] === section;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', String(isActive));
  });

  document.querySelectorAll<HTMLElement>('.section').forEach(el => {
    el.classList.toggle('active', el.id === `section-${section}`);
  });
}

document.querySelectorAll<HTMLButtonElement>('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const sec = btn.dataset['section'];
    if (sec) switchSection(sec);
  });
});

// ── Overview rendering ────────────────────────────────────────────────────────

function renderOverview(stats: HunterStats, findings: Finding[]): void {
  const vuln   = stats.vulnerableCount  ?? 0;
  const inconc = stats.inconclusiveCount ?? 0;
  const safe   = stats.protectedCount   ?? 0;
  const total  = findings.length;

  // Header stats
  elHstatTotal.textContent  = String(stats.totalRequests);
  elHstatVuln.textContent   = String(vuln);
  elHstatInconc.textContent = String(inconc);
  elHstatSafe.textContent   = String(safe);

  // Overview cards
  elOvVuln.textContent      = String(vuln);
  elOvInconc.textContent    = String(inconc);
  elOvSafe.textContent      = String(safe);
  elOvTotal.textContent     = String(stats.totalRequests);
  elOvEndpoints.textContent = String(stats.endpoints.length);

  // Nav finding count badge
  elNavFindingsCount.textContent = String(vuln > 0 ? vuln : total);
  elNavTrafficCount.textContent  = String(stats.totalRequests);

  // Endpoint list
  elOvEpList.innerHTML = '';
  if (stats.endpoints.length === 0) {
    elOvEpList.innerHTML = `<li style="color:var(--text-muted);font-size:11px;font-style:italic">No traffic captured yet</li>`;
  } else {
    for (const ep of stats.endpoints.slice(0, 8)) {
      const li = document.createElement('li');
      li.textContent = ep;
      elOvEpList.appendChild(li);
    }
  }

  // Severity donut (CSS conic-gradient)
  const sum = vuln + inconc + safe;
  if (sum === 0) {
    elDonutChart.style.background = `conic-gradient(var(--border-medium) 0deg 360deg)`;
  } else {
    const vulnDeg  = (vuln  / sum) * 360;
    const inconcDeg = vulnDeg + (inconc / sum) * 360;
    elDonutChart.style.background = `conic-gradient(
      var(--accent-red)    0deg ${vulnDeg.toFixed(1)}deg,
      var(--accent-yellow) ${vulnDeg.toFixed(1)}deg ${inconcDeg.toFixed(1)}deg,
      var(--accent-green)  ${inconcDeg.toFixed(1)}deg 360deg
    )`;
  }

  elDonutVuln.textContent  = `${vuln} Vulnerable`;
  elDonutInconc.textContent = `${inconc} Inconclusive`;
  elDonutSafe.textContent  = `${safe} Protected`;
}

// ── Findings table rendering ──────────────────────────────────────────────────

function getFilteredFindings(): Finding[] {
  let filtered = activeFilter === 'all'
    ? [...allFindings]
    : allFindings.filter(f => f.result.verdict === activeFilter);

  if (activeSort === 'severity') {
    filtered.sort((a, b) => {
      if (b.severityScore !== a.severityScore) return b.severityScore - a.severityScore;
      return b.result.testedAt - a.result.testedAt;
    });
  } else {
    filtered.sort((a, b) => b.result.testedAt - a.result.testedAt);
  }
  return filtered;
}

function renderFindingsTable(): void {
  const filtered = getFilteredFindings();

  if (filtered.length === 0) {
    elFindingsEmpty.style.display = '';
    elFindingsTable.style.display = 'none';
    return;
  }

  elFindingsEmpty.style.display = 'none';
  elFindingsTable.style.display = '';
  elFindingsTbody.innerHTML     = '';

  for (const finding of filtered) {
    const res = finding.result;
    const tr  = document.createElement('tr');
    tr.className = res.verdict;

    tr.innerHTML = `
      <td><span class="verdict-badge ${res.verdict}">${res.verdict}</span></td>
      <td><span class="op-name-cell" title="${escapeHtml(finding.operationName)}">${escapeHtml(finding.operationName)}</span></td>
      <td><span class="test-type-badge">${res.testType}</span></td>
      <td><span class="url-cell" title="${escapeHtml(finding.requestUrl)}">${escapeHtml(fmtUrl(finding.requestUrl))}</span></td>
      <td class="time-cell">${res.replayedStatus}</td>
      <td class="time-cell">${fmtTime(res.testedAt)}</td>
    `;

    tr.addEventListener('click', () => openDrawer(finding));
    elFindingsTbody.appendChild(tr);
  }
}

// ── Filter/sort controls ──────────────────────────────────────────────────────

document.querySelectorAll<HTMLButtonElement>('.filter-btn[data-filter]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll<HTMLButtonElement>('.filter-btn[data-filter]').forEach(b =>
      b.classList.remove('active'),
    );
    btn.classList.add('active');
    activeFilter = (btn.dataset['filter'] as typeof activeFilter) ?? 'all';
    renderFindingsTable();
  });
});

document.querySelectorAll<HTMLButtonElement>('.filter-btn[data-sort]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll<HTMLButtonElement>('.filter-btn[data-sort]').forEach(b =>
      b.classList.remove('active'),
    );
    btn.classList.add('active');
    activeSort = (btn.dataset['sort'] as typeof activeSort) ?? 'severity';
    renderFindingsTable();
  });
});

// ── Drawer ────────────────────────────────────────────────────────────────────

function openDrawer(finding: Finding): void {
  const res  = finding.result;
  const verdict = res.verdict;

  elDrawerOpName.textContent   = finding.operationName;
  elDrawerBadge.textContent    = verdict;
  elDrawerBadge.className      = `verdict-badge ${verdict}`;
  elDrawer.setAttribute('aria-hidden', 'false');

  // Diff entries to show
  const displayEntries = res.diff.entries
    .filter(e => e.changed || !isNullLike(e.replayedValue))
    .slice(0, 20);

  const diffRowsHtml = displayEntries.map(e => {
    const rowClass = !isNullLike(e.replayedValue) ? 'leaked-row' : e.changed ? 'changed-row' : '';
    const replClass = !isNullLike(e.replayedValue) ? 'leaked' : e.changed ? 'changed' : '';
    return `
      <tr class="${rowClass}">
        <td class="diff-path">${escapeHtml(e.path)}</td>
        <td class="diff-orig">${escapeHtml(String(e.originalValue ?? 'null'))}</td>
        <td class="diff-repl ${replClass}">${escapeHtml(String(e.replayedValue ?? 'null'))}</td>
      </tr>`;
  }).join('');

  const leakedChipsHtml = res.diff.leakedFields.length > 0
    ? `<div class="leaked-chips">
        ${res.diff.leakedFields.slice(0, 10).map(f =>
          `<span class="leaked-chip">${escapeHtml(f)}</span>`,
        ).join('')}
        ${res.diff.leakedFields.length > 10
          ? `<span class="leaked-chip">+${res.diff.leakedFields.length - 10} more</span>` : ''}
      </div>`
    : `<p style="font-size:11px;color:var(--text-muted)">No leaked fields detected.</p>`;

  elDrawerBody.innerHTML = `
    <!-- Meta grid -->
    <div>
      <div class="drawer-section-title">Details</div>
      <div class="drawer-meta-grid">
        <div class="drawer-meta-item">
          <div class="drawer-meta-label">Test Type</div>
          <div class="drawer-meta-value">${escapeHtml(res.testType)}</div>
        </div>
        <div class="drawer-meta-item">
          <div class="drawer-meta-label">HTTP Status</div>
          <div class="drawer-meta-value">${res.replayedStatus}</div>
        </div>
        <div class="drawer-meta-item">
          <div class="drawer-meta-label">Duration</div>
          <div class="drawer-meta-value">${fmtMs(res.replayedDurationMs)}</div>
        </div>
        <div class="drawer-meta-item">
          <div class="drawer-meta-label">Tested At</div>
          <div class="drawer-meta-value">${fmtTime(res.testedAt)}</div>
        </div>
        <div class="drawer-meta-item" style="grid-column:span 2">
          <div class="drawer-meta-label">Endpoint</div>
          <div class="drawer-meta-value" title="${escapeHtml(finding.requestUrl)}">${escapeHtml(finding.requestUrl)}</div>
        </div>
      </div>
    </div>

    <!-- Evidence -->
    <div>
      <div class="drawer-section-title">Evidence</div>
      <div class="evidence-box">${escapeHtml(res.evidence)}</div>
    </div>

    <!-- Leaked fields -->
    <div>
      <div class="drawer-section-title">Leaked Fields (${res.diff.leakedFields.length})</div>
      ${leakedChipsHtml}
    </div>

    <!-- Response diff -->
    ${displayEntries.length > 0 ? `
    <div>
      <div class="drawer-section-title">Response Diff — ${res.diff.entries.filter(e => e.changed).length} changed field(s)</div>
      <div style="overflow-x:auto;border:1px solid var(--border-subtle);border-radius:var(--radius-sm)">
        <table class="diff-table">
          <thead><tr><th>Path</th><th>Original</th><th>Replayed</th></tr></thead>
          <tbody>${diffRowsHtml}</tbody>
        </table>
      </div>
    </div>` : ''}

    <!-- cURL reproduction -->
    <div>
      <div class="drawer-section-title">Reproduction (cURL)</div>
      <div class="curl-block">
        <code class="curl-code" id="drawer-curl">${escapeHtml(finding.curl)}</code>
        <button class="btn-copy-curl" id="btn-copy-curl">Copy</button>
      </div>
    </div>

    <!-- Analyst note -->
    <div>
      <div class="drawer-section-title">Analyst Notes</div>
      <textarea class="note-textarea" id="drawer-note" placeholder="Add your analysis notes here…">${escapeHtml(finding.note)}</textarea>
      <div class="note-saved-hint" id="note-saved-hint">✓ Note saved</div>
    </div>
  `;

  // Copy curl handler
  const btnCopy = document.getElementById('btn-copy-curl')!;
  btnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(finding.curl).then(() => {
      btnCopy.textContent = 'Copied!';
      setTimeout(() => { btnCopy.textContent = 'Copy'; }, 1500);
    });
  });

  // Auto-save note on blur
  const noteArea = document.getElementById('drawer-note') as HTMLTextAreaElement;
  const noteSavedHint = document.getElementById('note-saved-hint')!;
  noteArea.addEventListener('blur', async () => {
    const note = noteArea.value;
    if (note === finding.note) return;
    finding.note = note;
    await browser.runtime.sendMessage({
      type:    'SAVE_FINDING_NOTE',
      payload: { findingId: finding.id, note },
    });
    noteSavedHint.classList.add('visible');
    setTimeout(() => noteSavedHint.classList.remove('visible'), 2000);
  });

  // Open overlay + drawer
  elDrawerOverlay.classList.add('open');
  elDrawer.classList.add('open');
  elDrawerOverlay.setAttribute('aria-hidden', 'false');
}

function closeDrawer(): void {
  elDrawer.classList.remove('open');
  elDrawerOverlay.classList.remove('open');
  elDrawer.setAttribute('aria-hidden', 'true');
  elDrawerOverlay.setAttribute('aria-hidden', 'true');
  // Deselect row
  document.querySelectorAll<HTMLTableRowElement>('.findings-table tbody tr.selected').forEach(r =>
    r.classList.remove('selected'),
  );
}

btnDrawerClose.addEventListener('click', closeDrawer);
elDrawerOverlay.addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeDrawer();
});

// ── Traffic feed rendering ────────────────────────────────────────────────────

function renderTrafficFeed(requests: CapturedRequest[]): void {
  // Remove old items
  elTrafficFeed.querySelectorAll('.dash-feed-item').forEach(el => el.remove());

  if (requests.length === 0) {
    elTrafficEmpty.style.display = '';
    return;
  }
  elTrafficEmpty.style.display = 'none';

  for (const req of requests.slice(0, 50)) {
    const opType  = inferOpType(req);
    const opName  = inferOpName(req);
    const risk    = req.analysis?.overallRisk ?? 'INFO';
    const status  = req.response?.status;
    const dur     = req.response?.durationMs;

    const item = document.createElement('div');
    item.className = 'dash-feed-item';
    item.innerHTML = `
      <div class="dash-op-badge ${opType}">${
        opType === 'mutation' ? 'MUT' : opType === 'sub' ? 'SUB' : 'QRY'
      }</div>
      <div class="dash-item-body">
        <div class="dash-item-name">${escapeHtml(opName)}</div>
        <div class="dash-item-url">${escapeHtml(fmtUrl(req.url))}</div>
      </div>
      <span class="dash-risk-badge ${risk.toLowerCase()}">${risk}</span>
      ${status != null ? `<span style="font-family:monospace;font-size:11px;color:${status < 400 ? 'var(--accent-green)' : 'var(--accent-red)'}">${status}</span>` : ''}
      ${dur != null ? `<span style="font-size:10px;color:var(--text-muted)">${fmtMs(dur)}</span>` : ''}
    `;
    elTrafficFeed.appendChild(item);
  }
}

// ── Schema rendering ──────────────────────────────────────────────────────────

function renderSchema(model: SchemaModel): void {
  const typeNames  = Object.keys(model.types);
  const totalFields = typeNames.reduce(
    (n, t) => n + Object.keys(model.types[t].fields).length, 0,
  );

  elNavSchemaCount.textContent   = String(typeNames.length);
  elSchemaFieldSummary.textContent = typeNames.length > 0
    ? `${typeNames.length} types · ${totalFields} fields · ${model.endpoints.length} endpoints`
    : '';

  // Remove old nodes
  elSchemaTreeDash.querySelectorAll('.schema-node').forEach(n => n.remove());

  if (typeNames.length === 0) {
    elSchemaEmptyDash.style.display = '';
    return;
  }
  elSchemaEmptyDash.style.display = 'none';

  for (const typeName of typeNames.sort()) {
    const schemaType = model.types[typeName];
    const fieldNames = Object.keys(schemaType.fields);

    const node = document.createElement('div');
    node.className = 'schema-node';
    node.innerHTML = `
      <div class="schema-node-header" role="button" tabindex="0" aria-expanded="false">
        <svg class="schema-chevron" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <path d="M4 2l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span class="schema-type-name-dash">${escapeHtml(typeName)}</span>
        <span class="schema-field-count-dash">${fieldNames.length} ${fieldNames.length === 1 ? 'field' : 'fields'}</span>
      </div>
      <div class="schema-fields-list" role="list">
        ${fieldNames.sort().map(fn => {
          const f = schemaType.fields[fn];
          const argsText = f.args.length > 0 ? `(${f.args.join(', ')})` : '';
          const opPills  = f.seenInOps
            .map(op => `<span class="schema-op-pill-dash ${op}">${op === 'subscription' ? 'sub' : op}</span>`)
            .join('');
          return `
            <div class="schema-field-row-dash" role="listitem">
              <span class="schema-field-name-dash">${escapeHtml(fn)}</span>
              ${argsText ? `<span class="schema-field-args-dash">${escapeHtml(argsText)}</span>` : ''}
              ${opPills}
            </div>`;
        }).join('')}
      </div>
    `;

    const header = node.querySelector('.schema-node-header')!;
    header.addEventListener('click', () => {
      node.classList.toggle('open');
      header.setAttribute('aria-expanded', String(node.classList.contains('open')));
    });
    header.addEventListener('keydown', e => {
      if ((e as KeyboardEvent).key === 'Enter' || (e as KeyboardEvent).key === ' ') {
        (header as HTMLElement).click();
      }
    });

    elSchemaTreeDash.appendChild(node);
  }
}

// ── Data loading ──────────────────────────────────────────────────────────────

async function refresh(): Promise<void> {
  const [requests, stats, schema, findings] = await Promise.all([
    browser.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS' }) as Promise<CapturedRequest[]>,
    browser.runtime.sendMessage({ type: 'GET_STATS' })             as Promise<HunterStats>,
    browser.runtime.sendMessage({ type: 'GET_SCHEMA' })            as Promise<SchemaModel>,
    browser.runtime.sendMessage({ type: 'GET_FINDINGS' })          as Promise<Finding[]>,
  ]);

  allRequests   = requests ?? [];
  allFindings   = findings ?? [];
  currentStats  = stats;
  currentSchema = schema;

  const safeStats: HunterStats = stats ?? {
    totalRequests: 0, endpoints: [], batchCount: 0, mutationCount: 0,
    queryCount: 0, riskCount: 0, vulnerableCount: 0, inconclusiveCount: 0, protectedCount: 0,
  };
  const safeSchema: SchemaModel = schema ?? { types: {}, endpoints: [], lastUpdated: 0 };

  renderOverview(safeStats, allFindings);
  renderFindingsTable();
  renderTrafficFeed(allRequests);
  renderSchema(safeSchema);
}

// ── Live updates from background ──────────────────────────────────────────────

browser.runtime.onMessage.addListener((raw: unknown) => {
  const msg = raw as HunterMessage;
  if (msg.type === 'GRAPHQL_REQUEST_CAPTURED' || msg.type === 'AUTH_TEST_RESULT') {
    refresh();
  }
});

// ── Export ────────────────────────────────────────────────────────────────────

btnExportMd.addEventListener('click', () => {
  if (allFindings.length === 0) return;
  const md = generateMarkdownReport(allFindings);
  downloadBlob(md, `graphql-hunter-report-${Date.now()}.md`, 'text/markdown');
});

btnExportJson.addEventListener('click', () => {
  if (allFindings.length === 0) return;
  const json = generateJsonReport(allFindings);
  downloadBlob(json, `graphql-hunter-report-${Date.now()}.json`, 'application/json');
});

btnClearFindings.addEventListener('click', async () => {
  if (!window.confirm('Delete all findings? This cannot be undone.')) return;
  await browser.runtime.sendMessage({ type: 'CLEAR_FINDINGS' });
  closeDrawer();
  await refresh();
});

// ── Init ──────────────────────────────────────────────────────────────────────

refresh();
