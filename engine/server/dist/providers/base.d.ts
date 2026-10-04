import type { ChatMessage, ChatCompletionResponse, ChatCompletionChunk, ChatToolDefinition, ChatToolChoice, Platform } from '@freellmapi/shared/types.js';
import type { QuotaObservationContext } from '../services/provider-quota.js';
import type { ExtendedSamplingOptions } from '../lib/sampling-params.js';
/** A provider HTTP error carrying the upstream status and, when the provider
 *  stated one, the parsed back-off so the router can bench the key for at least
 *  that long. The delay may come from the Retry-After header or from the error
 *  body — see providerHttpError. */
export interface ProviderHttpError extends Error {
    status?: number;
    retryAfterMs?: number;
    /** Explicit daily-window violation from structured upstream quota details. */
    dailyQuotaExhausted?: boolean;
}
/** Parse an HTTP `Retry-After` header (delta-seconds or an HTTP-date) into a
 *  millisecond delay, clamped to MAX_RETRY_AFTER_MS. Returns undefined when
 *  absent or unparseable. */
export declare function parseRetryAfterMs(value: string | null | undefined): number | undefined;
/**
 * The back-off a provider stated inside its error BODY, in milliseconds.
 *
 * Not every provider uses the Retry-After header. Gemini answers a 429 with
 * `error.details[]` carrying a `google.rpc.RetryInfo` whose `retryDelay` is
 * "17s", and several OpenAI-compatible tiers only say it in prose. Those hints
 * were being thrown away: the body is flattened to a single message string
 * before it reaches the router, so a provider that told us exactly when to come
 * back got the same heuristic cooldown ladder as one that said nothing.
 */
export declare function parseStatedRetryMs(body: unknown): number | undefined;
/** Build an error for a non-OK upstream response, capturing the status and any
 *  stated back-off. Used by every provider adapter so the proxy can honor a
 *  provider's explicit hint when it sets the cooldown.
 *
 *  `body` is the already-parsed error payload the caller used to build
 *  `message`. Only a delay is read out of it and only a number is kept — the
 *  body itself is never retained, so nothing extra reaches a log or the
 *  attempt trace. The Retry-After header still wins when both are present: it
 *  is the standard channel, and preferring it keeps existing behavior exactly
 *  as it was. */
export declare function providerHttpError(res: Response, message: string, body?: unknown): ProviderHttpError;
export interface CompletionOptions extends ExtendedSamplingOptions {
    model?: string;
    temperature?: number;
    max_tokens?: number;
    top_p?: number;
    stop?: string | string[];
    tools?: ChatToolDefinition[];
    tool_choice?: ChatToolChoice;
    parallel_tool_calls?: boolean;
    stream_options?: {
        include_usage?: boolean;
    };
    /** Remaining context budget (context_window − estimated_input_tokens) for
     *  this route. resolveMaxTokens clamps max_tokens to fit. */
    contextBudget?: number;
    /** Per-call HTTP timeout override. Not part of the OpenAI wire format (it is
     * stripped before the request body is built); used by the probe script so
     * NVIDIA's 15-60s serverless cold starts don't read as failures. */
    timeoutMs?: number;
    /** Abort signal for the gateway's OWN client (request socket closed). The
     * proxy surfaces thread it here so a disconnect cancels the upstream fetch
     * AND any in-progress body/stream read — tokens stop burning and the
     * in-flight lease frees immediately instead of when the read happens to
     * finish. Composed with the per-attempt timeout in fetchWithTimeout; never
     * serialized into the request body. */
    signal?: AbortSignal;
}
/** Per-call abort/timeout wiring for fetchWithTimeout. */
export interface ProviderFetchOptions {
    /** Client-disconnect signal, composed with the per-attempt timeout via
     * AbortSignal.any. Unlike the timeout it is never disarmed at headers, so it
     * also aborts body reads and stream iteration through undici. */
    signal?: AbortSignal;
    /** What the per-attempt timeout bounds:
     *  - 'headers' (default, historical): the abort timer dies the moment
     *    response HEADERS arrive — right for streams, whose body legitimately
     *    outlives any fixed deadline (readSseStream's stall watchdog owns
     *    mid-stream hangs, the client signal owns "nobody is listening").
     *  - 'request': the deadline stays armed across the body read too, so a 200
     *    whose body never finishes aborts at timeoutMs instead of hanging
     *    res.json() forever. Use for non-streaming calls, which read the whole
     *    body as one unit. */
    timeoutBounds?: 'headers' | 'request';
}
/** Per-stream timeout wiring for readSseStream (#584). */
export interface SseStreamOptions {
    /** The chat timeout the adapter gave fetchWithTimeout for this request
     * (options.timeoutMs override included). Becomes the first-byte grace
     * budget, floored at the stall budget — see firstByteBudgetMs. Defaults to
     * fetchWithTimeout's own default, providerTimeoutMs(platform, 15000). */
    firstByteTimeoutMs?: number;
    /** Mid-stream inactivity budget; defaults to streamStallTimeoutMs(platform)
     * (per-platform env > global env > 90s). 0 disables the watchdog. */
    stallTimeoutMs?: number;
}
export interface KeyValidationFailure {
    valid: false;
    /** Provider-supplied reason suitable for health logs and the local keys UI. */
    error: string;
}
export type KeyValidationResult = boolean | KeyValidationFailure;
export declare abstract class BaseProvider {
    abstract readonly platform: Platform;
    abstract readonly name: string;
    /** Providers whose free tier needs no API key (e.g. Kilo's anonymous gateway).
     * When true, the gateway stores a sentinel key row so routing still considers
     * the platform "configured", and the provider omits the Authorization header
     * on outgoing requests. Defaults to false; set by subclasses. */
    keyless: boolean;
    abstract chatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): Promise<ChatCompletionResponse>;
    abstract streamChatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): AsyncGenerator<ChatCompletionChunk>;
    abstract validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
    /**
     * Turn a conventional 401/403 validation response into a diagnostic result.
     * Providers still return a simple boolean when no useful error body exists,
     * but preserving the upstream message here lets the health service persist
     * and display the reason instead of reducing every failure to "invalid".
     */
    protected validationResult(res: Response): Promise<KeyValidationResult>;
    protected fetchWithTimeout(url: string, init: RequestInit, timeoutMs?: number, fetchOpts?: ProviderFetchOptions): Promise<Response>;
    protected makeId(): string;
    /**
     * One reader.read() bounded by the mid-stream inactivity watchdog (#553).
     * Shared by readSseStream and adapters that parse their own wire format
     * (google.ts) so every stream gets the same stall semantics:
     * PROVIDER_STREAM_STALL_TIMEOUT_MS (per-platform override
     * PROVIDER_STREAM_STALL_TIMEOUT_<PLATFORM>, #584), default 90s, 0 disables.
     * Client-abort rejections pass through untouched — undici errors the body
     * with the request signal's reason, so a disconnect surfaces here as the
     * marked error from newClientAbortError, not as a stall. `timeoutMessage`
     * lets the first-byte read report its distinct wording (#584).
     */
    protected readWithStallTimeout<T>(read: () => Promise<T>, inactivityTimeoutMs: number, timeoutMessage?: string): Promise<T>;
    /**
     * Budget for the FIRST read of a streaming body (issue #584): the platform's
     * chat timeout is already "how slow may the first token be" — tuned per
     * platform at registration and env-overridable via PROVIDER_TIMEOUT_<PLATFORM>
     * — but on streams it is disarmed the moment response HEADERS arrive, and
     * providers like NVIDIA NIM send SSE headers instantly then prefill for
     * minutes. Floored at the stall budget so a platform with a short chat
     * timeout never gets a STRICTER first read than the pre-#584 watchdog gave
     * it. 0 on either side (env-disabled chat timeout, or disabled watchdog)
     * means the first read is unbounded — the client signal still owns
     * "nobody is listening".
     */
    protected firstByteBudgetMs(chatTimeoutMs: number, stallTimeoutMs: number): number;
    /** Distinct wording for a first-byte timeout (vs a mid-stream stall) so the
     * attempt-trace error_summary tells slow prefill apart from a dead stream. */
    protected firstByteTimeoutMessage(budgetMs: number): string;
    /**
     * Shared SSE reader for OpenAI-wire streaming endpoints (#231 audit).
     *
     * Hardened against the upstream failure modes observed live:
     *  - Inactivity timeout: fetchWithTimeout's abort timer dies the moment
     *    response HEADERS arrive, so a provider that stalls mid-body used to
     *    hang the client forever. Each read now has its own deadline. The FIRST
     *    read gets a grace budget derived from the platform's chat timeout
     *    (#584) — SSE headers can arrive instantly while the model prefills a
     *    long prompt for minutes, which is slow, not stalled.
     *  - Abrupt EOF: a stream that ends without `[DONE]` AND without any
     *    `finish_reason` is a truncated generation, not a completion. It used
     *    to end the generator silently (truncation logged as success); it now
     *    throws a retryable error so the proxy can fail over or report it.
     *    Providers that skip `[DONE]` but do send a terminal finish_reason
     *    (several compat shims) still complete normally.
     *
     * Malformed data lines are skipped, matching previous behavior.
     *
     * The frames additionally pass through the inline `<think>` extractor
     * (lib/think-tags.ts): DeepSeek-style models that serialize their reasoning
     * trace INTO delta.content as a leading `<think>…</think>` block get it
     * moved to delta.reasoning_content, so downstream surfaces never render
     * thinking as answer text. Streams without the tag are forwarded verbatim.
     */
    protected readSseStream(res: Response, opts?: SseStreamOptions): AsyncGenerator<ChatCompletionChunk>;
    private readSseFrames;
}
//# sourceMappingURL=base.d.ts.map