// ─────────────────────────────────────────────────────────────────────────────
// page-hook.ts — Page-world Fetch / XHR Interceptor
//
// This script is injected as a <script src="..."> tag into the target page
// by content.ts. It runs in the PAGE WORLD — it has access to window.fetch
// and XMLHttpRequest but CANNOT use any browser extension APIs.
//
// It monkey-patches fetch() and XMLHttpRequest to detect GraphQL payloads
// and forward them to the content script via window.postMessage.
//
// The content script then relays them to the background via runtime.sendMessage.
// ─────────────────────────────────────────────────────────────────────────────

// No imports — this must be a fully standalone bundle.

(function () {
  'use strict';

  const MSG_TYPE = '__GQL_HUNTER__';

  // ── Detection helpers ─────────────────────────────────────────────────────

  function isGQLObject(obj: unknown): boolean {
    if (!obj || typeof obj !== 'object') return false;
    if (Array.isArray(obj)) {
      return obj.length > 0 && (obj as unknown[]).every(isGQLObject);
    }
    const o = obj as Record<string, unknown>;
    return typeof o['query'] === 'string' && (o['query'] as string).trim().length > 0;
  }

  function tryParseGQL(
    body: unknown,
  ): Record<string, unknown> | Record<string, unknown>[] | null {
    if (typeof body !== 'string') return null;
    try {
      const parsed: unknown = JSON.parse(body);
      return isGQLObject(parsed)
        ? (parsed as Record<string, unknown> | Record<string, unknown>[])
        : null;
    } catch {
      return null;
    }
  }

  function emit(
    url:    string,
    method: string,
    body:   Record<string, unknown> | Record<string, unknown>[],
    source: 'fetch' | 'xhr',
  ): void {
    window.postMessage({ type: MSG_TYPE, url, method, body, source }, '*');
  }

  // ── Patch fetch ───────────────────────────────────────────────────────────

  const origFetch = window.fetch.bind(window);

  (window as Window).fetch = function (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const url =
      typeof input === 'string'
        ? input
        : input instanceof URL
        ? input.href
        : (input as Request).url;

    const bodyStr = typeof init?.body === 'string' ? init.body : null;
    if (bodyStr) {
      const gql = tryParseGQL(bodyStr);
      if (gql) emit(url, (init?.method ?? 'POST').toUpperCase(), gql, 'fetch');
    }

    return origFetch(input, init);
  };

  // ── Patch XMLHttpRequest ──────────────────────────────────────────────────

  const OrigOpen = XMLHttpRequest.prototype.open;
  const OrigSend = XMLHttpRequest.prototype.send;

  // Store URL + method on the XHR instance between open() and send()
  XMLHttpRequest.prototype.open = function (
    method: string,
    url: string | URL,
    ...rest: unknown[]
  ): void {
    (this as unknown as Record<string, string>)['_gql_url']    = url.toString();
    (this as unknown as Record<string, string>)['_gql_method'] = method.toUpperCase();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (OrigOpen as (...a: unknown[]) => void).apply(this, [method, url, ...rest]);
  };

  XMLHttpRequest.prototype.send = function (
    body?: Document | XMLHttpRequestBodyInit | null,
  ): void {
    if (typeof body === 'string') {
      const gql = tryParseGQL(body);
      if (gql) {
        const ctx    = this as unknown as Record<string, string>;
        const url    = ctx['_gql_url']    ?? '';
        const method = ctx['_gql_method'] ?? 'POST';
        emit(url, method, gql, 'xhr');
      }
    }
    return (OrigSend as (b?: Document | XMLHttpRequestBodyInit | null) => void).apply(this, [body]);
  };

  console.debug('[GraphQL Hunter] Page hook active on', location.origin);
})();
