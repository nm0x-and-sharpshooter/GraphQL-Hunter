// ─────────────────────────────────────────────────────────────────────────────
// Message types for communication between extension contexts:
//   background ↔ popup  (browser.runtime.sendMessage)
//   background ↔ content (browser.tabs.sendMessage)
//
// Using a discriminated union ensures exhaustive handling in every switch.
// ─────────────────────────────────────────────────────────────────────────────

import type { CapturedRequest, HunterStats, GraphQLRequestBody, SchemaModel } from './graphql';

// ── Message definitions (discriminated union) ─────────────────────────────────

/** Sent from background → popup when a new request is captured live. */
export interface MsgRequestCaptured {
  type:    'GRAPHQL_REQUEST_CAPTURED';
  payload: CapturedRequest;
}

/** Popup → background: fetch all stored requests. */
export interface MsgGetRequests {
  type: 'GET_CAPTURED_REQUESTS';
}

/** Background → popup: response to GET_CAPTURED_REQUESTS. */
export interface MsgRequestsResponse {
  type:    'CAPTURED_REQUESTS_RESPONSE';
  payload: CapturedRequest[];
}

/** Popup → background: wipe all stored data. */
export interface MsgClearRequests {
  type: 'CLEAR_REQUESTS';
}

/** Popup → background: fetch summary statistics. */
export interface MsgGetStats {
  type: 'GET_STATS';
}

/** Background → popup: response to GET_STATS. */
export interface MsgStatsResponse {
  type:    'STATS_RESPONSE';
  payload: HunterStats;
}

/** Content script → background: captured via page-world fetch/XHR hook. */
export interface PageHookPayload {
  url:    string;
  method: string;
  body:   GraphQLRequestBody | GraphQLRequestBody[];
  source: 'fetch' | 'xhr';
}

export interface MsgPageHookRequest {
  type:    'PAGE_HOOK_REQUEST';
  payload: PageHookPayload;
}

/** Popup → background: fetch the current schema model. */
export interface MsgGetSchema {
  type: 'GET_SCHEMA';
}

/** Background → popup: response to GET_SCHEMA. */
export interface MsgSchemaResponse {
  type:    'SCHEMA_RESPONSE';
  payload: SchemaModel;
}

/** Popup → background: wipe the schema model. */
export interface MsgClearSchema {
  type: 'CLEAR_SCHEMA';
}

// ── Union type ────────────────────────────────────────────────────────────────

export type HunterMessage =
  | MsgRequestCaptured
  | MsgGetRequests
  | MsgRequestsResponse
  | MsgClearRequests
  | MsgGetStats
  | MsgStatsResponse
  | MsgPageHookRequest
  | MsgGetSchema
  | MsgSchemaResponse
  | MsgClearSchema;

export type MessageType = HunterMessage['type'];
