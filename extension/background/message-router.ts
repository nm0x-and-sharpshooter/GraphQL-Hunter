// ─────────────────────────────────────────────────────────────────────────────
// message-router.ts — Runtime message handler for background script
//
// Handles all browser.runtime.onMessage calls from popup / content scripts.
// Each handler is async and returns a value (the promise resolves as the
// sendMessage response).
// ─────────────────────────────────────────────────────────────────────────────

import browser from 'webextension-polyfill';
import { getRequests, clearRequests, getStats, getSchema, clearSchema, saveAuthTestResult, saveFinding, getFindings, updateFindingNote, clearFindings } from './storage';
import { runAuthTest } from '../analysis/auth-tester';
import { generateCurl } from '../analysis/evidence-utils';
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

        case 'RUN_AUTH_TEST':
          return (async () => {
            const { requestId, testType } = message.payload;
            // Look up the original request by ID
            const allRequests = await getRequests();
            const target      = allRequests.find(r => r.id === requestId);
            if (!target) {
              return { ok: false, error: `Request ${requestId} not found.` };
            }
            // Run the test, persist auth-test result, and save as standalone finding
            const result = await runAuthTest(target, testType);
            await saveAuthTestResult(requestId, result);

            // Day 5: also persist as a deduplicated Finding with curl + metadata
            const bodies  = Array.isArray(target.body) ? target.body : [target.body];
            const opName  = target.analysis?.operations[0]?.operationName
                          ?? bodies[0]?.operationName
                          ?? 'anonymous';
            const curl    = generateCurl(target, testType);
            await saveFinding(result, target.url, opName, curl);

            await broadcast({ type: 'AUTH_TEST_RESULT', payload: result });
            return result;
          })();

        case 'PAGE_HOOK_REQUEST':
          if (pageHookHandler) {
            return pageHookHandler(message.payload, sender.tab?.id ?? -1).then(() => ({ ok: true }));
          }
          return Promise.resolve({ ok: true });

        // ── Day 5: Finding management ───────────────────────────────────────
        case 'GET_FINDINGS':
          return getFindings();

        case 'SAVE_FINDING_NOTE':
          return updateFindingNote(
            message.payload.findingId,
            message.payload.note,
          ).then(() => ({ ok: true }));

        case 'CLEAR_FINDINGS':
          return clearFindings().then(() => ({ ok: true }));

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
