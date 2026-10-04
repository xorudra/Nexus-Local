/**
 * Concurrent in-flight requests allowed per key, or null for unlimited.
 *
 * Some free tiers meter concurrency per credential rather than per minute, so
 * parallel streams on one key mostly 429 each other. But most do not, and
 * capping by default would serialise every provider and cost real throughput —
 * so this is opt-in. There is deliberately no built-in per-platform table: the
 * providers that behave this way are not documented well enough to assert a
 * number for them here, and a wrong default is worse than none.
 *
 * `MAX_CONCURRENT_REQUESTS_PER_KEY_<PLATFORM>` sets it for one platform;
 * `MAX_CONCURRENT_REQUESTS_PER_KEY` sets a fallback for all of them.
 */
export declare function getKeyConcurrencyLimit(platform: string): number | null;
/** Requests this process currently has in flight against one platform+key. */
export declare function inFlightForKey(platform: string, keyId: number, now?: number): number;
/** False when this key already has its allowed number of requests in the air.
 *  Always true when no cap is configured, which is the default. */
export declare function canUseKeyConcurrency(platform: string, keyId: number, now?: number): boolean;
/** Take a lease for an attempt about to be dispatched. Returns the id to release. */
export declare function acquireLease(platform: string, modelId: string, keyId: number, tokens: number, now?: number): number;
/** Release a lease. Idempotent, so a double release from overlapping cleanup
 *  paths is harmless. */
export declare function releaseLease(leaseId: number): void;
/** Test seam: drop all leases. */
export declare function resetLeases(): void;
export declare function canMakeRequest(platform: string, modelId: string, keyId: number, limits: {
    rpm: number | null;
    rpd: number | null;
    tpm: number | null;
    tpd: number | null;
}): boolean;
export declare function canUseTokens(platform: string, modelId: string, keyId: number, estimatedTokens: number, limits: {
    tpm: number | null;
    tpd: number | null;
}): boolean;
export interface WindowLimits {
    rpm: number | null;
    rpd: number | null;
    tpm: number | null;
    tpd: number | null;
}
/** Drop the memoised window snapshot. Tests use it to make a write visible
 *  immediately; production relies on the TTL. */
export declare function invalidateWindowUsage(): void;
/**
 * Share of its binding rate-limit window a model has already consumed, as a
 * 0..1 fraction (0 idle, 1 exhausted). null = no opinion: the model declares no
 * window limits, has no routable key to measure, or the database is unreachable.
 *
 * Which key's numbers to report matters, and the answer is the same one the
 * dashboard's usage badge settled on (#921): the guardrail asks "how close is
 * this model to being unroutable", so it must follow the key the router would
 * pick NEXT, not the worst key on the account. A platform with one exhausted
 * key and one idle key routes perfectly well, so we take the ELIGIBLE key with
 * the MOST headroom.
 *
 * In-flight leases are deliberately not counted. They exist to close the
 * check-then-act race on the hard gates; this is a steering signal averaged over
 * a whole window, and folding a per-request quantity into a cached snapshot
 * would buy noise, not accuracy.
 */
export declare function modelWindowUsedFraction(model: {
    platform: string;
    modelId: string;
    keyId?: number | null;
}, limits: WindowLimits, now?: number): number | null;
export declare function getProviderDailyRequestCap(platform: string): number | null;
/** Account-wide requests-per-minute cap, or null when the provider has none.
 *  `PROVIDER_MINUTE_REQUEST_CAP_<PLATFORM>=0` disables the gate for that platform. */
export declare function getProviderMinuteRequestCap(platform: string): number | null;
export declare function getProviderDailyTokenCap(platform: string): number | null;
export declare function providerDailyRequestCount(platform: string, keyId: number, now?: number): number;
export declare function canUseProvider(platform: string, keyId: number, now?: number): boolean;
/** Requests in the last minute for a provider account+key, across every model. */
export declare function providerMinuteRequestCount(platform: string, keyId: number, now?: number): number;
export declare function canUseProviderMinute(platform: string, keyId: number, now?: number): boolean;
export declare function providerDailyTokenCount(platform: string, keyId: number, now?: number): number;
export declare function canUseProviderTokens(platform: string, keyId: number, modelId: string, estimatedTokens: number, now?: number): boolean;
export declare function recordRequest(platform: string, modelId: string, keyId: number): void;
export declare function recordTokens(platform: string, modelId: string, keyId: number, tokens: number): void;
export type CooldownSource = 'heuristic' | 'authoritative' | 'credit' | 'tier';
export declare const COOLDOWN_CEILING_KEY = "routing_cooldown_ceiling_ms";
export declare const MIN_COOLDOWN_CEILING_MS: number;
export declare const MAX_COOLDOWN_CEILING_MS: number;
/** The configured ceiling in ms, or null when unset/invalid (no cap). Read
 *  through a try/catch like every other DB touch in this module so a failure
 *  before the DB is ready degrades to "no cap" instead of throwing mid-route. */
export declare function getCooldownCeilingMs(): number | null;
/** null clears the ceiling (back to the uncapped ladder). */
export declare function setCooldownCeilingMs(value: number | null): void;
/** Apply the operator ceiling to one of OUR heuristic bench durations. */
export declare function capCooldownMs(durationMs: number): number;
export declare function getNextCooldownDuration(platform: string, modelId: string, keyId: number): number;
export declare const PAYMENT_REQUIRED_COOLDOWN_MS: number;
/** The 402 bench with the operator ceiling applied (#952). */
export declare function getPaymentRequiredCooldownMs(): number;
export declare const MODEL_FORBIDDEN_COOLDOWN_MS: number;
/** The 403 tier bench with the operator ceiling applied (#952). */
export declare function getModelForbiddenCooldownMs(): number;
export declare function recentHitCount(platform: string, modelId: string, keyId: number, now: number, windowMs?: number): number;
export interface CooldownDecision {
    durationMs: number;
    source: CooldownSource;
}
export declare const LOCAL_ENDPOINT_COOLDOWN_MS = 5000;
export declare function isLocalEndpointKey(keyId: number): boolean;
/** Test hook: the locality verdict is cached per key id for the process
 *  lifetime (see above); tests that rewrite api_keys rows need a reset. */
export declare function resetKeyLocalityCache(): void;
export interface CooldownLimitOptions {
    /** Whether the triggering failure is an actual provider quota signal (a real
     *  429 / rate-limit-classified error — see isRateLimitSignal in
     *  lib/error-classify.ts). Timeouts, 5xx and transport errors are retryable
     *  but carry no quota information, so they must not feed the null-limits
     *  exhaustion heuristic below (#592) — they get the short transient bench.
     *  Defaults to true: legacy callers without error context (fusion's
     *  empty-completion benches) keep their pre-#592 behavior. */
    quotaSignal?: boolean;
}
export declare function getCooldownDurationForLimit(platform: string, modelId: string, keyId: number, limits: {
    rpd: number | null;
    tpd: number | null;
}, retryAfterMs?: number | null, opts?: CooldownLimitOptions): number;
/**
 * Same verdict as getCooldownDurationForLimit, plus the provenance the
 * cooldown-probe recovery job needs: 'authoritative' when an explicit provider
 * Retry-After actually determined the expiry (a fact — never probed early),
 * 'heuristic' when the duration is our own transient/escalation guess (probe-
 * eligible). A Retry-After SHORTER than our bench does not make the cooldown
 * authoritative: everything past the provider's own retry time is our guess.
 */
export declare function getCooldownDecisionForLimit(platform: string, modelId: string, keyId: number, limits: {
    rpd: number | null;
    tpd: number | null;
}, retryAfterMs?: number | null, opts?: CooldownLimitOptions): CooldownDecision;
/**
 * Delete every already-expired cooldown, on disk and in memory, and return how
 * many rows went. Expiry is otherwise purely lazy: isOnCooldown drops a row only
 * when something asks about that exact (platform, model, key), so a row whose
 * model was retired, whose key was deleted, or that simply outlived a process
 * that had every route benched is never collected — the table only grows, and
 * every cooldown query (status rollups, the probe scan, penalty inspector) pays
 * for the dead rows. Called once at boot (index.ts) so a restart starts clean.
 */
export declare function cleanupExpiredCooldowns(now?: number): number;
export declare function setCooldown(platform: string, modelId: string, keyId: number, durationMs?: number, source?: CooldownSource): void;
export declare function isOnCooldown(platform: string, modelId: string, keyId: number): boolean;
export interface ActiveCooldown {
    platform: string;
    modelId: string;
    keyId: number;
    expiresAtMs: number;
    remainingMs: number;
}
/**
 * Active cooldowns for the given keys, grouped by key id. Batched into one query
 * so the dashboard can render "why is this key idle?" without N round-trips.
 * Without this, a key benched by an escalated cooldown (up to 24h) is invisible:
 * it reads as healthy and enabled while the router silently skips it.
 */
export declare function getActiveCooldownsForKeys(keyIds: number[], now?: number): Map<number, ActiveCooldown[]>;
/**
 * Drop every cooldown for one key, in memory and on disk, and return how many
 * were cleared. Escalated cooldowns can bench a key for up to 24h off a single
 * bad window; an operator who has fixed the cause (raised a quota, waited out a
 * provider incident) otherwise has no way back except restarting and waiting.
 */
export declare function clearCooldownsForKey(keyId: number): number;
/**
 * Drop EVERY cooldown (all keys, all models), the escalation-ladder counters
 * and the null-limits hit windows — the "my whole pool is stuck" escape hatch
 * (#952). Returns how many active benches were lifted. Penalties and the
 * model-failure windows live elsewhere; services/penalty-inspector.ts
 * composes all three into one clear.
 */
export declare function clearAllCooldowns(now?: number): number;
export interface ProbeableCooldown {
    platform: string;
    modelId: string;
    keyId: number;
    expiresAtMs: number;
    setAtMs: number | null;
}
/**
 * Active cooldowns whose expiry is OUR OWN guess ('heuristic'), i.e. the only
 * ones probe-based early recovery may touch. Authoritative/credit/tier rows are
 * excluded at the query so the prober cannot even see them. Deliberately
 * DB-only, no in-memory fallback: the probe job is a best-effort optimisation,
 * and when the DB is unavailable the right amount of probing is none.
 */
export declare function getProbeableCooldowns(now?: number): ProbeableCooldown[];
/**
 * Clear ONE model+key cooldown before its timer expires, after a probe showed
 * the key is serving again. Narrower than clearCooldownsForKey (the operator
 * override): the escalation history in cooldownHits is deliberately kept, so a
 * key that 429s again right after an early recovery re-enters the ladder where
 * it left off instead of starting back at 2 minutes.
 */
export declare function clearCooldownEarly(platform: string, modelId: string, keyId: number): void;
/**
 * Soonest moment any active cooldown expires, in ms since epoch, or null when
 * nothing is cooling down. Used to tell an exhausted caller roughly when to
 * retry (#423) instead of the bare "wait for rate limits to reset".
 */
export declare function getSoonestCooldownExpiry(now?: number): number | null;
export declare function getRateLimitStatus(platform: string, modelId: string, keyId: number, limits: {
    rpm: number | null;
    rpd: number | null;
    tpm: number | null;
    tpd: number | null;
}): {
    rpm: {
        used: number;
        limit: number | null;
    };
    rpd: {
        used: number;
        limit: number | null;
    };
    tpm: {
        used: number;
        limit: number | null;
    };
};
export type LearnedLimitKind = 'tpm' | 'tpd' | 'rpm' | 'rpd';
export interface LearnedLimit {
    kind: LearnedLimitKind;
    limit: number;
}
/**
 * Pure parser: pull a provider-reported ceiling out of an error message. Returns
 * null unless BOTH a numeric "Limit N" and a confident axis (TPM/TPD/RPM/RPD)
 * are present — guessing the axis would write the wrong column and mis-route
 * every future request, so we refuse to guess.
 */
export declare function parseProviderLimit(message: string | undefined | null): LearnedLimit | null;
/**
 * Persist a provider-reported limit onto the model row, but ONLY when it makes
 * us more conservative: fill a NULL (unknown) limit, or LOWER an existing one
 * that was too high. Never raises a limit — hitting a ceiling means our pre-check
 * already let too much through, so the true limit is at or below what we used.
 * Returns the learned limit when a row was actually changed, else null.
 * DB-guarded (no-op when the DB is unavailable), like the rest of this module.
 */
export declare function learnLimitFromError(modelDbId: number, err: {
    message?: string;
}): LearnedLimit | null;
//# sourceMappingURL=ratelimit.d.ts.map