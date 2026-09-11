// ─────────────────────────────────────────────────────────────────────────────
// content.ts — Content script
//
// Injects the page-world interceptor (page-hook.js) into the target page.
// Listens for postMessage events from page-hook.js and forwards captured
// GraphQL requests to the background script via browser.runtime.sendMessage.
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import type { PageHookPayload } from '../types/messages';

console.debug('[GraphQL Hunter] Content script active on', location.origin);

/**
 * Injects page-hook.js into the host page context so it can patch
 * window.fetch and XMLHttpRequest.
 */
function injectPageHook(): void {
  try {
    const script = document.createElement('script');
    script.src = browser.runtime.getURL('content/page-hook.js');
    script.onload = () => script.remove();
    (document.head || document.documentElement).appendChild(script);
  } catch (err) {
    console.warn('[GraphQL Hunter] Failed to inject page hook:', err);
  }
}

injectPageHook();

// ── Bridge: page window.postMessage → background runtime.sendMessage ──────────

window.addEventListener('message', (event: MessageEvent) => {
  // Only accept messages from the current window
  if (event.source !== window || !event.data || event.data.type !== '__GQL_HUNTER__') {
    return;
  }

  const { url, method, body, source } = event.data as {
    url:    string;
    method: string;
    body:   unknown;
    source: 'fetch' | 'xhr';
  };

  const payload: PageHookPayload = {
    url,
    method,
    body: body as PageHookPayload['body'],
    source,
  };

  browser.runtime.sendMessage({
    type: 'PAGE_HOOK_REQUEST',
    payload,
  }).catch((err: unknown) => {
    // Background script might be re-initialising or popup closed — safe to ignore
    console.debug('[GraphQL Hunter] Failed to relay page hook request:', err);
  });
});
