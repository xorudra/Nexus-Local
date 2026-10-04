import type { RouteResult } from '../services/router.js';
import { type CooldownDecision } from '../services/ratelimit.js';
import { type AttemptTraceRecord } from './attempt-trace.js';
export declare const FALLBACK_MAX_RETRIES = 20;
export declare const MODEL_FAILURE_WINDOW_MS: number;
export declare const MODEL_FAILURE_THRESHOLD = 3;
export declare const MODEL_FAILURE_COOLDOWN_MS: number;
export declare const DEFAULT_FALLBACK_TIME_BUDGET_MS = 45000;
export declare const HEDGE_BENCH_MIN_SILENT_FRACTION = 0.75;
export declare const FALLBACK_TIME_BUDGET_SETTING = "fallback_time_budget_ms";
export declare function getFallbackTimeBudgetMs(): number;
export interface FallbackState {
    skipKeys: Set<string>;
    skipModels: Set<number>;
    skipPlatforms: Set<string>;
    observedTotalTokens?: number;
    observedInputTokens?: number;
    wantsTools?: boolean;
    toolRejects?: Set<string>;
    modelNotFoundPlatforms: Map<string, Set<number>>;
}
/** Total for the next dispatch. Input-only observations still need output space. */
export declare function fallbackRoutingTokens(state: FallbackState, estimatedTotal: number, outputReserve: number): number;
export declare function newFallbackState(): FallbackState;
export declare const MODEL_NOT_FOUND_PLATFORM_LIMIT = 3;
export declare function msUntilNextUtcMidnight(now?: number): number;
/** Gemini daily quotas reset at midnight Pacific, including DST transitions.
 * https://ai.google.dev/gemini-api/docs/rate-limits */
export declare function msUntilNextPacificMidnight(now?: number): number;
/**
 * The one true cooldown-duration selection after a retryable upstream failure:
 *   - 402 out-of-credits  → a full day (PAYMENT_REQUIRED_COOLDOWN_MS)
 *   - 403 model-not-on-tier → a full day (MODEL_FORBIDDEN_COOLDOWN_MS), because a
 *     tier/subscription gate won't clear on the next minute window (issue #256).
 *     Both honour the operator's cooldown ceiling (#952): relay endpoints emit
 *     these for transient reasons, and a day is then far too long.
 *   - a 429 that says the DAILY free allocation is spent (Cloudflare "used up
 *     your daily free allocation of 10,000 neurons") → benched until the next
 *     UTC midnight, like the 402 path. The old transient 90s cooldown made the
 *     router re-pick a dead-for-the-day provider all day long. An explicit
 *     provider Retry-After wins over the midnight heuristic: rolling daily
 *     windows (Groq RPD "try again in 7m12s" with a Retry-After header) reset
 *     well before midnight, and the provider knows its own reset time best.
 *     Gemini daily violations instead wait until midnight Pacific; a shorter
 *     RetryInfo can refer to a simultaneous per-minute violation.
 *   - anything else → the transient/daily escalation ladder, honoring the
 *     provider's Retry-After as a floor (getCooldownDurationForLimit).
 */
export declare function cooldownForError(route: RouteResult, err: any): number;
/**
 * cooldownForError plus the provenance tag the cooldown-probe recovery job
 * keys off (see CooldownSource in services/ratelimit.ts): 402 → 'credit' and
 * 403 → 'tier' (a key-validation probe passing proves nothing about credits or
 * tier, so those are never probed); a daily-quota bench → 'authoritative' (the
 * expiry is the provider's own reset time, whether from Retry-After or the
 * UTC-midnight convention — a fact, not a guess); everything else defers to
 * getCooldownDecisionForLimit, which tags 'authoritative' only when an explicit
 * Retry-After actually determined the expiry.
 */
export declare function cooldownDecisionForError(route: RouteResult, err: any): CooldownDecision;
export declare const TRUNCATION_STREAK_LIMIT = 3;
export declare const TRUNCATION_BENCH_MS: number;
export declare function resetTruncationStreaks(): void;
export declare const EMPTY_COMPLETION_STREAK_LIMIT = 3;
export declare function resetEmptyCompletionStreaks(): void;
/** Drop every model's sliding failure window. Module state outlives a test
 *  case, so without this a case inherits the previous one's failure counts and
 *  trips the threshold early — clearing `rate_limit_cooldowns` alone does not
 *  reach it. */
export declare function resetModelFailureWindows(): void;
/** Operator clear (#952): drop every model's failure window and report how many
 *  models were mid-streak. The benches those streaks produced are ordinary
 *  cooldown rows and go with clearAllCooldowns. */
export declare function clearModelFailureWindows(): number;
/**
 * Apply the full per-key failure bookkeeping shared by every surface after a
 * retryable failure:
 *   - rule out the WHOLE model for the rest of the request on a 404 (removed
 *     upstream) or 403 (off this key's tier) — a sibling key would fail it the
 *     same way (PR #111 / issue #256);
 *   - bench this model+key via cooldownForError;
 *   - demote the model in the scorer ONLY when the failure exhausted it — i.e.
 *     no sibling key can still serve it (#454 gate). skipKeys already contains
 *     the just-failed key here, preserving #479's "count budget across keys"
 *     semantics: hasOtherUsableKey excludes both the failed key and skipKeys;
 *   - learn a provider-reported ceiling (e.g. a Groq 413 "TPM: Limit 30000")
 *     from the error body so the next pre-check fails over before the 413.
 *
 * Reasoning-truncation exemption: an error thrown with `skipBench: true` (a
 * reasoning model that spent the whole max_tokens budget on hidden reasoning,
 * finish_reason 'length') still fails over — the key is skipped for THIS
 * request — but is NOT a provider-health signal, so no cooldown, no model
 * penalty, and no limit-learning are recorded. Benching those was costing
 * healthy models a 90s cooldown + a scorer penalty per truncated turn. The
 * exemption is streak-bounded (#751): from the EMPTY_COMPLETION_STREAK_LIMITth
 * consecutive empty completion on the same model+key it stops applying, until
 * a success (or a normally-penalized failure) resets the streak.
 *
 * Returns whether the skipBench exemption held for this failure, so the loop
 * can keep the breaker in lockstep with the bench decision.
 *
 * Callers add the just-failed key to skipKeys via this function (do not pre-add).
 */
export declare function recordRetryableFailure(route: RouteResult, err: any, state: FallbackState, now?: number): boolean;
export declare const AUTH_FAILURE_COOLDOWN_MS: number;
/**
 * Bookkeeping for an auth-fatal (401 / invalid key) attempt: skip the key for
 * this request, bench the model+key for the health-cycle window, and start an
 * immediate revalidation. Deliberately NO model penalty and NO limit-learning —
 * a bad key says nothing about the model's health.
 */
export declare function recordAuthFailure(route: RouteResult, state: FallbackState): void;
/**
 * The success-side accounting every surface runs after a completed attempt:
 * count the request + its tokens against the model+key's rate-limit windows and
 * clear the model's 429 penalty. `rateLimitTokens` is whatever the surface metered
 * (the provider's usage.total_tokens for non-stream, an estimate for stream).
 */
export declare function recordUpstreamSuccess(route: RouteResult, rateLimitTokens: number, state?: FallbackState): void;
export type AttemptErrorClass = 'auth' | 'out_of_credits' | 'daily_quota_exhausted' | 'model_not_found' | 'forbidden' | 'context_too_large' | 'provider_bad_request' | 'empty_completion' | 'format_ignored' | 'invalid_tool_arguments' | 'timeout' | 'rate_limited' | 'upstream_error' | 'error';
export interface AttemptRecord {
    platform: string;
    modelId: string;
    keyOrdinal: number;
    errorClass: AttemptErrorClass;
}
export declare function classifyAttemptError(err: any): AttemptErrorClass;
export declare const EXPOSE_FALLBACK_DETAIL_SETTING = "expose_fallback_detail_header";
export declare function isFallbackDetailHeaderEnabled(): boolean;
/**
 * One `platform/model keyN=outcome t=<start>+<duration>ms msg=<summary>` segment
 * per hop, `; `-joined — the same leading shape as X-Fallback-Trail so the two
 * headers line up when read together.
 *
 * The summary is the already-redacted `errorSummary`, never `err.message`. Its
 * semicolons become commas because `; ` is the record separator; nothing else
 * is escaped, which keeps the value readable, and `safeHeaderValue` handles any
 * non-ASCII on the way out.
 */
export declare function formatAttemptDetail(records: AttemptTraceRecord[]): string;
export declare function formatAttemptTrail(attempts: AttemptRecord[]): string;
/**
 * Set the failover diagnostics headers every surface stamps on its responses:
 * X-Fallback-Attempts (how many hops failed before this response) and
 * X-Fallback-Trail (what each hop was and why it failed). Until now the trail
 * only reached clients inside exhaustion error MESSAGES — a request that
 * eventually succeeded gave no hint that it burned five hops first, which is
 * exactly the case an operator wants to notice. Values go through
 * safeHeaderValue so a non-ASCII or control-laden model id can neither inject
 * header lines nor make Node reject the response outright (#619).
 *
 * When EXPOSE_FALLBACK_DETAIL_SETTING is on, X-Fallback-Detail joins them with
 * per-hop timings and the redacted provider message. Every caller runs inside
 * the request's AsyncLocalStorage scope, so the trace is readable here without
 * threading it through all five surfaces.
 *
 * Note what the detail header can and cannot contain: at flush time the trace
 * holds exactly the hops that already FAILED, each with final timings. The hop
 * currently being served is recorded only after dispatch returns — after
 * res.json(), or after the whole stream has finished — so its duration is not
 * knowable while headers are still open, on either path.
 */
export declare function setFallbackHeaders(res: {
    setHeader(name: string, value: string): void;
}, failedAttempts: number, trail: AttemptRecord[] | undefined): void;
export interface ExhaustionBody {
    status: number;
    type: string;
    message: string;
    kind: 'auth' | 'bad_request' | 'rate_limit' | 'unavailable' | 'context_too_large' | 'model_not_found' | 'upstream';
    code?: string;
    retryAtMs?: number;
}
/**
 * The OpenAI-compatible `error` object for an exhaustion body — shared by every
 * OpenAI-shaped surface so the wire shape (message/type/code/retryAtMs) cannot
 * drift between them.
 */
export declare function exhaustionErrorPayload(body: ExhaustionBody): {
    message: string;
    type: string;
    code?: string;
    retryAtMs?: number;
};
/**
 * Stamp the standard retry headers for an exhaustion body: a Retry-After of
 * ceil((retryAtMs - now) / 1000) seconds when the body carries a concrete
 * retry time. Callers must only invoke this before headers are flushed (i.e.
 * never on a committed SSE stream).
 */
export declare function setExhaustionHeaders(res: {
    setHeader(name: string, value: string): void;
}, body: ExhaustionBody, now?: number): void;
export interface ExhaustionContext {
    attempts?: AttemptRecord[];
    timedOut?: boolean;
    budgetMs?: number;
    breakerFails?: number;
}
/**
 * The shared exhaustion response body — the single failure-kind → terminal-
 * status ladder every surface renders. Aggregated over the per-attempt failure
 * classes (most-specific first):
 *   - Every attempt failed auth (401/invalid key) → 502 provider_error saying the
 *     PROVIDER keys are bad — distinct from a rate-limit exhaustion, and never
 *     'authentication_error' (which would wrongly blame the CLIENT's key).
 *   - Every attempt died on a context/prompt-too-large rejection → 413: no
 *     candidate can fit this request; retrying cannot help, shrinking it can.
 *   - Every attempt got a model-not-found/gone from its provider → 404: the
 *     model has been removed upstream everywhere we route it. (No 410 — the
 *     catalog keeps no removal tombstones, so "verifiably existed before" is
 *     not determinable here.)
 *   - A chain that died on a DEGRADED-function 400 (NVIDIA NIM, #522) → 503:
 *     provider capacity, not a bad request.
 *   - A request every routed provider rejected as invalid → 400
 *     invalid_request_error, not a misleading rate-limit exhaustion.
 *   - Circuit-breaker stop → 503 (the pool looks unhealthy; retry later).
 *   - Every attempt unavailable-until-known-time (rate limits, benched
 *     quotas/credits/tiers) → 429 rate_limit_error with `retryAtMs` (soonest
 *     cooldown expiry) for a matching Retry-After header.
 *   - Mixed/other upstream failures (5xx, timeouts, transport errors) → 502
 *     provider_error: the UPSTREAMS failed. Never 500 — that status is
 *     reserved for our own bugs.
 * All bodies carry the attempt trail (what was tried, per attempt) and, where
 * meaningful, the soonest-cooldown-reset hint.
 */
export declare function exhaustedRetryError(lastError: any, maxRetries?: number, ctx?: ExhaustionContext): ExhaustionBody;
export declare function routingExhaustionBody(routeErr: any): ExhaustionBody;
export type DispatchOutcome = 'done' | 'committed';
/** Per-attempt handles the loop hands to dispatch. */
export interface DispatchContext {
    /**
     * Cancel this attempt's time-budget hedge. Idempotent and always safe to
     * call, including when hedging is not armed at all. See FallbackHooks.dispatch.
     */
    disarmHedge(): void;
}
export interface ExhaustionInfo {
    attempts: AttemptRecord[];
    timedOut: boolean;
}
export interface FallbackHooks {
    maxRetries?: number;
    timeBudgetMs?: number;
    breakerLimit?: number;
    attemptLog?: AttemptRecord[];
    logIdentity?: {
        surface: string;
        requestId?: string;
        requestedModel?: string;
    };
    clientGone?: () => boolean;
    abortInFlight?: () => void;
    state: FallbackState;
    /**
     * Pick a route for this attempt. Reads state.skipKeys / state.skipModels /
     * state.skipPlatforms.
     * Throws the router's RouteError when the pool is exhausted before any
     * upstream is tried (caught by the loop → onRoutingExhausted).
     */
    route(attempt: number): RouteResult;
    /**
     * Run one attempt against the chosen route. Return 'done' on success or
     * 'committed' when a stream already sent bytes and handled its own mid-stream
     * error. THROW a (possibly synthetic) provider error — an upstream HTTP error,
     * or an "empty completion" / "unparseable inline tool-call dialect" Error the
     * classifier already treats as retryable — to trigger failover; a
     * non-retryable throw becomes onFatal. A pre-commit failure MUST throw (not
     * return 'committed') so the loop can fail over invisibly. The loop enforces
     * this contract: any other return value is a programming error and fails
     * loudly instead of silently swallowing the request.
     *
     * `ctx.disarmHedge()` cancels the time-budget hedge for THIS attempt. Call it
     * the moment the attempt proves it is alive (first byte / headers flushed):
     * past that point the budget must not cancel it, because the answer is
     * already on its way and killing it would truncate a healthy response for no
     * failover benefit. Streaming surfaces are expected to call it; a
     * non-streaming attempt has nothing to disarm until it returns.
     */
    dispatch(route: RouteResult, attempt: number, ctx: DispatchContext): Promise<DispatchOutcome>;
    /** Trace + log a per-attempt failure (per-surface scope + logRequest args). */
    logFailure(route: RouteResult, err: any, attempt: number): void;
    /** Render a non-retryable provider error (per-surface body/status). `attempt`
     *  is the failing attempt's index = the number of prior fallback hops. */
    onFatal(route: RouteResult, err: any, attempt: number): void;
    /**
     * Render exhaustion when route() threw. `exhaustion` is always the shared
     * honest-status body: built from the attempt trail when at least one attempt
     * ran, or from routeErr's routing diagnostics (routingExhaustionBody) when
     * routing gave up before any upstream was tried. `lastError` is null in the
     * zero-attempt case; `routeErr` is passed for logging/diagnostics.
     */
    onRoutingExhausted(lastError: any, routeErr: any, exhaustion: ExhaustionBody, info: ExhaustionInfo): void;
    /** Render exhaustion after the attempt cap or the time budget was hit. */
    onExhausted(exhaustion: ExhaustionBody, info: ExhaustionInfo): void;
}
/**
 * The shared attempt loop. Owns iteration, the wall-clock retry budget, the
 * routeRequest-exhaustion path, the auth/retryable/fatal classification, the
 * per-failure bookkeeping (recordRetryableFailure / recordAuthFailure), the
 * attempt trail, and the final exhaustion body. Everything surface-specific —
 * request translation, stream framing, error-body shape, context handoff, group
 * routing — lives in the hooks.
 */
export declare function runFallbackLoop(hooks: FallbackHooks): Promise<void>;
//# sourceMappingURL=fallback-loop.d.ts.map