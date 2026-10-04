import type { ChatMessage } from '@freellmapi/shared/types.js';
export declare const CACHE_ENABLED_SETTING = "response_cache_enabled";
/**
 * Master switch. Default off so adopting the cache is an explicit choice. The
 * settings-table value wins when present (dashboard toggle, no restart), then
 * the RESPONSE_CACHE env var, then off.
 */
export declare function isCacheEnabled(): boolean;
/**
 * Write-through to SQLite. Only meaningful when the cache itself is on, so an
 * install that never enabled caching persists nothing and the feature is inert.
 * Separately switchable because persisting plaintext model responses to disk is
 * a privacy decision an operator may want to decline while still caching.
 */
export declare function cachePersistenceEnabled(): boolean;
/** Entry lifetime. Default 1h: long enough to absorb retries and agent re-runs,
 *  short enough that a refreshed catalog or key changes answers soon after. */
export declare function cacheTtlMs(): number;
/** Above this temperature a request wants variety, so it is never cached.
 *  Default 1.0 caches everything when enabled (max quota savings); lower it to
 *  restrict caching to (near-)deterministic calls. */
export declare function cacheMaxTemperature(): number;
/** Hard cap on stored entries; least-recently-used are evicted past this.
 *  Bounds memory use. */
export declare function cacheMaxEntries(): number;
export declare function isCacheableTemperature(temperature?: number | null): boolean;
export type CacheDirective = 'default' | 'off' | 'on';
export declare function parseCacheDirective(header: string | string[] | undefined, cacheControl?: string | string[] | undefined): CacheDirective;
/** Resolve the global switch + per-request directive into a single yes/no. */
export declare function cacheActive(directive: CacheDirective): boolean;
export interface CacheKeyInput {
    model: string | undefined;
    messages: ChatMessage[];
    temperature?: number;
    top_p?: number;
    max_tokens?: number;
    tools?: unknown;
    tool_choice?: unknown;
    stop?: unknown;
    response_format?: unknown;
    n?: unknown;
    seed?: unknown;
    presence_penalty?: unknown;
    frequency_penalty?: unknown;
    logit_bias?: unknown;
    logprobs?: unknown;
    top_logprobs?: unknown;
    reasoning_effort?: unknown;
    compression?: unknown;
}
export declare function computeCacheKey(input: CacheKeyInput): string;
export interface CachedResponse {
    body: unknown;
    platform: string;
    modelId: string;
    keyId: number | null;
    promptTokens: number;
    completionTokens: number;
}
export interface StoreInput {
    body: unknown;
    platform: string;
    modelId: string;
    keyId: number | null;
    promptTokens: number;
    completionTokens: number;
}
/**
 * Test-only: run the queued write-through immediately instead of on the next
 * tick, so a synchronous test can assert on what actually reached SQLite.
 */
export declare function __flushPersistenceForTests(): void;
/**
 * Test-only: drop the in-memory LRU while leaving the SQLite table intact, the
 * way a process restart does. (clearCache() is the user-facing flush and wipes
 * both, so it cannot stand in for a restart.) Pending write-through is drained
 * first, since a real restart's writes had already landed. Streaming entries
 * are memory-only (never written through), so a restart drops them too.
 */
export declare function __resetMemoryForTests(): void;
/**
 * Look up a cached completion. Returns null on a miss or when the entry has aged
 * past the TTL (expired entries are deleted lazily on read, in memory and on
 * disk). A hit bumps the entry's hit_count and moves it to most-recently-used.
 */
export declare function getCachedResponse(cacheKey: string, now?: number): CachedResponse | null;
/**
 * Store a successful completion. Overwrites any existing entry for the key (a
 * re-generation refreshes the cached answer, its TTL, and its hit count).
 * Enforces the entry cap by evicting the least-recently-used entries. Best-
 * effort: an unserializable body is skipped so caching can never break a
 * request that already succeeded.
 *
 * SQLite persistence: when the cache is on, the entry is also written through
 * to the response_cache table so it survives a restart (the daily quota-reset
 * re-run pattern). The write is deferred to the next tick and best-effort, so
 * it never sits on — or throws into — the proxy hot path; a DB failure degrades
 * to in-memory-only, exactly as before.
 */
export declare function storeCachedResponse(cacheKey: string, input: StoreInput, now?: number): void;
/**
 * Reload unexpired entries from SQLite into the in-memory LRU, bounded by
 * RESPONSE_CACHE_MAX_ENTRIES. Called once at startup (after initDb) from both
 * boot paths, server/src/index.ts and desktop/src/server-host.ts; expired rows
 * are purged opportunistically. Best-effort: any DB error leaves the cache
 * empty (memory-only), matching the pre-persistence behavior.
 */
export declare function loadCacheFromDb(now?: number): void;
/**
 * Ceiling on one cached stream's replay payload. A single long answer must not
 * be able to pin megabytes of SSE text in memory, and a stream past this size
 * is cheap to regenerate relative to what it costs to hold. The caller stops
 * buffering at this point too (proxy.ts), so an oversize stream never fully
 * materializes; this is the store-side backstop.
 */
export declare const STREAM_CACHE_MAX_BYTES: number;
export interface CachedStreamResponse {
    /** The whole SSE sequence, ready to write in one go. */
    sse: string;
    platform: string;
    modelId: string;
    keyId: number | null;
    promptTokens: number;
    completionTokens: number;
}
export interface StoreStreamInput {
    frames: string[];
    platform: string;
    modelId: string;
    keyId: number | null;
    promptTokens: number;
    completionTokens: number;
}
/**
 * Look up a cached stream. Returns null on a miss or when the entry has aged
 * past the TTL. A hit bumps hit_count and moves the entry to MRU, and — like
 * the JSON lookup — counts into the process-wide hit/miss tallies behind the
 * dashboard's hit rate, so streaming traffic is not invisible there.
 */
export declare function getCachedStreamResponse(cacheKey: string, now?: number): CachedStreamResponse | null;
/**
 * Store a completed SSE frame sequence for replay. The frames are the verbatim
 * `data: {...}\n\n` lines (including the final `[DONE]`) the client received,
 * concatenated, so a hit reproduces the stream byte-for-byte. Best-effort like
 * the JSON store: an empty or oversize sequence is silently skipped, and the
 * entry shares the JSON store's entry cap.
 */
export declare function storeCachedStreamResponse(cacheKey: string, input: StoreStreamInput, now?: number): void;
export interface CacheStats {
    /**
     * Entries held across BOTH stores (JSON completions + streaming replays),
     * which is also what the shared RESPONSE_CACHE_MAX_ENTRIES cap bounds. One
     * prompt asked both streaming and non-streaming therefore counts twice —
     * they are two independent replayable artifacts, and two slots of the cap.
     */
    entries: number;
    /** Hits accumulated by the entries currently held, restored from SQLite. */
    totalHits: number;
    /** Hits ARE the savings: each one avoided a full provider round-trip. */
    estimatedRequestsSaved: number;
    savedPromptTokens: number;
    savedCompletionTokens: number;
    /** Lookups since this process started — the two halves of the ratio below. */
    lookupHits: number;
    lookupMisses: number;
    /** 0..1 share of this process's lookups that hit (no lookups yet → 0). */
    hitRate: number;
}
/**
 * Aggregate cache stats for the dashboard. "saved" tokens are the provider
 * tokens that hits avoided spending: hit_count x the entry's token counts,
 * summed, i.e. the free-tier quota the cache gave back. Those ride on the
 * entries, so they survive a restart along with the persisted rows.
 *
 * hitRate is deliberately computed from the process-lifetime lookup tallies
 * instead of totalHits: totalHits only counts the entries still held, so an
 * eviction (or a TTL expiry) would silently retire hits that really happened
 * and drag the reported rate down forever.
 */
export declare function getCacheStats(): CacheStats;
/**
 * Drop every cached entry, in memory AND on disk. Returns the number removed.
 * The persisted table has to go too: DELETE /api/cache is how an operator
 * forces fresh answers (changed keys, a bad reply, a privacy request), and a
 * flush that left the rows behind would resurrect all of it on the next
 * restart. Queued write-through is discarded for the same reason. Runs inline
 * rather than deferred: this is an admin route, not the proxy hot path.
 */
export declare function clearCache(): number;
//# sourceMappingURL=cache.d.ts.map