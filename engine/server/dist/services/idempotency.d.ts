import type { ChatMessage } from '@freellmapi/shared/types.js';
/** Replay window for completed idempotent responses (default 24h). */
export declare function idempotencyTtlMs(): number;
export declare function hashIdempotencyKey(key: string): string;
/** Canonical fingerprint of the request content that produced a response. */
export declare function computeIdempotencyFingerprint(input: {
    model?: string;
    messages: ChatMessage[];
    temperature?: number | null;
    top_p?: number | null;
    max_tokens?: number | null;
    tools?: unknown;
    tool_choice?: unknown;
}): string;
export type IdempotencyClaimResult = {
    kind: 'replay';
    status: number;
    body: unknown;
} | {
    kind: 'conflict';
} | {
    kind: 'miss';
};
/**
 * Attempt to claim a completed idempotent response for the given key hash.
 *
 * Returns:
 *   - { kind: 'replay', ... } when a completed claim with the SAME fingerprint
 *     exists and is still inside the replay window — the caller should replay
 *     it verbatim without touching a provider.
 *   - { kind: 'conflict' } when a completed claim exists but its fingerprint
 *     differs — the caller must return 409 idempotency_key_conflict.
 *   - { kind: 'miss' } when there is no usable claim — proceed normally and
 *     persist the result on success.
 */
export declare function lookupIdempotencyReplay(keyHash: string, fingerprint: string, now?: number): IdempotencyClaimResult;
/**
 * Persist a completed response for future replays. Replaces any previous claim
 * for the same key hash. Expired rows are swept lazily for this key first.
 */
export declare function storeIdempotencyResult(keyHash: string, fingerprint: string, status: number, body: unknown, executionId?: string, now?: number): void;
/**
 * Delete an idempotency claim (e.g. after a failed generation that the caller
 * does not want replayed). Fail-safe.
 */
export declare function clearIdempotencyResult(keyHash: string): void;
/** Normalize an Idempotency-Key header: trim, non-empty, ≤ 255 UTF-8 bytes. */
export declare function normalizeIdempotencyKey(raw: string | string[] | undefined): string | null;
//# sourceMappingURL=idempotency.d.ts.map