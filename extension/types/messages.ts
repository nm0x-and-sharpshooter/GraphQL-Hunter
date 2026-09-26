// ─────────────────────────────────────────────────────────────────────────────
// Message types for communication between extension contexts:
//   background ↔ popup  (browser.runtime.sendMessage)
//   background ↔ content (browser.tabs.sendMessage)
//
// Using a discriminated union ensures exhaustive handling in every switch.
// ─────────────────────────────────────────────────────────────────────────────

import type { CapturedRequest, HunterStats, GraphQLRequestBody, SchemaModel, AuthTestType, AuthTestResult, Finding, AttackType, AttackJob } from './graphql';

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

/** Popup → background: run an auth test against a captured request. */
export interface MsgRunAuthTest {
  type:    'RUN_AUTH_TEST';
  payload: { requestId: string; testType: AuthTestType };
}

/** Background → popup: auth-test result (broadcast + direct response). */
export interface MsgAuthTestResult {
  type:    'AUTH_TEST_RESULT';
  payload: AuthTestResult;
}

// ── Day 5: Finding management messages ───────────────────────────────────────

/** Popup/dashboard → background: fetch all persisted findings. */
export interface MsgGetFindings {
  type: 'GET_FINDINGS';
}

/** Background → popup/dashboard: response to GET_FINDINGS. */
export interface MsgFindingsResponse {
  type:    'FINDINGS_RESPONSE';
  payload: Finding[];
}

/** Dashboard → background: attach/update an analyst note on a finding. */
export interface MsgSaveFindingNote {
  type:    'SAVE_FINDING_NOTE';
  payload: { findingId: string; note: string };
}

/** Popup/dashboard → background: wipe all persisted findings. */
export interface MsgClearFindings {
  type: 'CLEAR_FINDINGS';
}

// ── Day 6: Attack Engine messages ───────────────────────────────────────────

/** Popup → background: launch an active attack against a captured request. */
export interface MsgRunAttack {
  type:    'RUN_ATTACK';
  payload: {
    requestId:    string;
    attackType:   AttackType;
    /** If true, send auth headers along with attack payloads. */
    preserveAuth: boolean;
    /** Optional depth override for DEPTH_BOMB attacks (default 8). */
    depthOverride?: number;
  };
}

/** Background → popup: completed attack job result (broadcast + direct response). */
export interface MsgAttackResult {
  type:    'ATTACK_RESULT';
  payload: AttackJob;
}

/** Popup/dashboard → background: fetch all stored attack jobs. */
export interface MsgGetAttackJobs {
  type: 'GET_ATTACK_JOBS';
}

/** Background → popup/dashboard: response to GET_ATTACK_JOBS. */
export interface MsgAttackJobsResponse {
  type:    'ATTACK_JOBS_RESPONSE';
  payload: AttackJob[];
}

/** Popup/dashboard → background: wipe all stored attack jobs. */
export interface MsgClearAttackJobs {
  type: 'CLEAR_ATTACK_JOBS';
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
  | MsgClearSchema
  | MsgRunAuthTest
  | MsgAuthTestResult
  | MsgGetFindings
  | MsgFindingsResponse
  | MsgSaveFindingNote
  | MsgClearFindings
  | MsgRunAttack
  | MsgAttackResult
  | MsgGetAttackJobs
  | MsgAttackJobsResponse
  | MsgClearAttackJobs;

export type MessageType = HunterMessage['type'];
