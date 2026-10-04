import type { Db } from '../db/types.js';
/** Trailing-slash-insensitive endpoint identity, matching how base_url is stored. */
export declare function normalizeBaseUrl(raw: string): string;
/** The scope token for a custom endpoint; '' means "not endpoint-scoped". */
export declare function endpointScopeForBaseUrl(baseUrl: string | null | undefined): string;
/**
 * The scope a model bound to `keyId` belongs to. '' when the key is gone or
 * carries no base_url — a legacy custom row that predates per-endpoint binding
 * keeps the un-scoped identity it has always had, so nothing about it changes.
 */
export declare function endpointScopeOfKey(db: Db, keyId: number | null | undefined): string;
/**
 * A short, typable handle for a scope, used only for naming: the host (with
 * port) plus path, slugified. Derived purely from the scope, so it is stable —
 * adding or removing OTHER endpoints never renames an existing one.
 *
 *   https://relay-a.example.com/v1  →  relay-a.example.com-v1
 *   http://127.0.0.1:11434/v1       →  127.0.0.1-11434-v1
 */
export declare function endpointHandle(scope: string): string;
/**
 * The bucket key for reliability/speed stats and the routing round-robin.
 * Unchanged (`platform:model_id`) for every catalog model and for un-scoped
 * legacy custom rows; endpoint-qualified only for rows that actually carry a
 * scope, so a single-endpoint install keeps its existing history verbatim.
 */
export declare function modelStatsKey(platform: string, modelId: string, endpointScope: string | null | undefined): string;
export declare const ENDPOINT_ID_SEPARATOR = "#";
/**
 * The endpoint-qualified model id a client can send to pin ONE relay's copy:
 * `custom:deepseek-v3.1#relay-a.example.com-v1`. Null for rows with no scope,
 * whose plain `platform:model_id` member id is already unambiguous — which is
 * why a single-endpoint install never sees a qualified id anywhere.
 */
export declare function qualifiedModelMemberId(platform: string, modelId: string, endpointScope: string | null | undefined): string | null;
/**
 * Whether `requested` names this row's endpoint after the separator. Accepts
 * the handle or the raw base_url (with or without scheme / trailing slash), so
 * a user who pastes the endpoint URL they typed into the dashboard is right.
 */
export declare function endpointRefMatches(requested: string, endpointScope: string): boolean;
//# sourceMappingURL=endpoint-scope.d.ts.map