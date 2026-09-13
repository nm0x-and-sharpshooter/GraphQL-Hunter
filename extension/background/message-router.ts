// ─────────────────────────────────────────────────────────────────────────────
// message-router.ts — Runtime message handler for background script
//
// Handles all browser.runtime.onMessage calls from popup / content scripts.
// Each handler is async and returns a value (the promise resolves as the
// sendMessage response).
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import { getRequests, clearRequests, getStats, getSchema, clearSchema } from './storage';
import type { HunterMessage, PageHookPayload } from '../types/messages';

export type PageHookHandler = (payload: PageHookPayload, tabId: number) => Promise<void>;

let pageHookHandler: PageHookHandler | null = null;

export function onPageHookCaptured(handler: PageHookHandler): void {
  pageHookHandler = handler;
}

export function startMessageRouter(): void {
  browser.runtime.onMessage.addListener(
    (rawMessage: unknown, sender: browser.Runtime.MessageSender): Promise<unknown> | true => {
      const message = rawMessage as HunterMessage;

      switch (message.type) {
        case 'GET_CAPTURED_REQUESTS':
          return getRequests();

        case 'CLEAR_REQUESTS':
          return clearRequests().then(() => ({ ok: true }));

        case 'GET_STATS':
          return getStats();

        case 'GET_SCHEMA':
          return getSchema();

        case 'CLEAR_SCHEMA':
          return clearSchema().then(() => ({ ok: true }));

        case 'PAGE_HOOK_REQUEST':
          if (pageHookHandler) {
            return pageHookHandler(message.payload, sender.tab?.id ?? -1).then(() => ({ ok: true }));
          }
          return Promise.resolve({ ok: true });

        default:
          // Not a message we handle — let Firefox know we didn't respond.
          return true;
      }
    },
  );

  console.log('[GraphQL Hunter] Message router active.');
}

/**
 * Broadcast a message to all extension contexts (popup, devtools panels).
 * Silently ignores "no receiver" errors — the popup may not be open.
 */
export async function broadcast(message: HunterMessage): Promise<void> {
  try {
    await browser.runtime.sendMessage(message);
  } catch {
    // Popup not open — ignore
  }
}
