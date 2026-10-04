import type { ChatMessage, ChatCompletionResponse, ChatCompletionChunk, Platform } from '@freellmapi/shared/types.js';
import { BaseProvider, type CompletionOptions, type KeyValidationResult } from './base.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
export { isAnonymousCredential } from '../lib/credential.js';
/**
 * Whether a base URL points at Moonshot's own API. Moonshot documents an
 * assistant-message `partial: true` prefill flag that no other OpenAI-compatible
 * upstream understands, and there is no built-in moonshot platform — Kimi
 * models are otherwise served by Groq, Cloudflare, OpenRouter, Hugging Face,
 * Ollama, ... — so the flag is gated on the endpoint host, never on the model
 * id. Returns false for anything that does not parse as a URL. (#1038)
 */
export declare function isMoonshotEndpoint(baseUrl: string): boolean;
/**
 * Some free-tier upstreams (notably Pollinations) answer HTTP 200 but put an
 * out-of-credits / top-up notice in the assistant message instead of returning
 * a 402. That reads as a successful completion, so the fallback loop never
 * rotates off the dead key (#pollinations-inband). Detect the notice so callers
 * can throw a payment-required error and fail over. Kept deliberately tight —
 * requires the credits phrase AND a top-up/quest/Pollinations marker — so a
 * genuine reply that merely discusses credits does not trip it.
 */
export declare function inBandCreditsError(text: string | null | undefined): string | null;
/**
 * Generic provider for platforms that use an OpenAI-compatible API.
 * Covers: Groq, Cerebras, NVIDIA NIM, Mistral, OpenRouter,
 * GitHub Models, Fireworks AI.
 */
export declare class OpenAICompatProvider extends BaseProvider {
    readonly platform: Platform;
    readonly name: string;
    private readonly baseUrl;
    private readonly extraHeaders;
    private readonly validateUrl?;
    /** Per-provider HTTP timeout override. OpenAI-compatible gateways often buffer
     * non-streaming responses until generation completes, and reasoning models can
     * take >15s before first byte. Default 60000. */
    private readonly timeoutMs;
    /** NVIDIA NIM models reject any request that permits parallel tool calls with
     * `400 This model only supports single tool-calls at once!`. When set, pin
     * parallel_tool_calls to false whenever tools are in play. See issue #255. */
    private readonly forceSingleToolCall;
    /** True only for a custom endpoint whose host is Moonshot's own API; see
     * isMoonshotEndpoint(). Gates the assistant `partial` prefill flag (#1038). */
    private readonly forwardsPartial;
    constructor(opts: {
        platform: Platform;
        name: string;
        baseUrl: string;
        extraHeaders?: Record<string, string>;
        validateUrl?: string;
        timeoutMs?: number;
        keyless?: boolean;
        forceSingleToolCall?: boolean;
    });
    /** Resolve the parallel_tool_calls flag to send upstream. For providers that
     * only accept single tool calls (NVIDIA NIM), force `false` whenever tools are
     * present so the model never tries to emit two at once and 400s; otherwise pass
     * the caller's value through unchanged. See issue #255. */
    private resolveParallelToolCalls;
    /** Some providers (Groq especially) reject a model's tool call with a 400
     * `tool_use_failed` when the model emitted it as inline DIALECT TEXT
     * (`<function=NAME{...}</function>`, Hermes/Qwen XML, etc.) that the provider's
     * own parser couldn't convert — but they hand back the raw text in
     * `error.failed_generation`. Weaker tool models (e.g. groq llama-3.3-70b) hit
     * this constantly, dead-ending an agent's whole turn even though the call is
     * perfectly recoverable. Reuse the same inline-dialect rescue the proxy already
     * applies to streamed text: parse `failed_generation` into structured
     * tool_calls so the turn succeeds instead of failing over (or exhausting the
     * chain when every enabled tool model behaves the same way). See issue #264. */
    private rescueFailedGeneration;
    /** Extract the useful text from an upstream error body. Most providers put it
     * at error.message, but NVIDIA NIM answers RFC7807-style ({"title": ...,
     * "detail": "Function id '...': DEGRADED function cannot be invoked"}) — the
     * old error.message-only read collapsed that to "Bad Request", so neither the
     * logs nor the error classifier could ever see the DEGRADED marker (#522). */
    private upstreamErrorText;
    /** Anonymous access sends NO Authorization header: keyless providers
     * (Kilo's anonymous free tier) holding the stored `no-key` sentinel, and
     * custom endpoints whose stored credential is the same sentinel with auth
     * off. Sending `Bearer no-key` upstream is never right — upstreams read it
     * as an invalid key. A REAL key saved on a keyless platform is used instead
     * of the anonymous path, and a real key on a custom endpoint still gets its
     * bearer (#1331): the presence of a credential decides at request time —
     * Kilo, OVH and AI Horde all accept both modes per their docs. */
    private authHeader;
    /** Requesty's Leanstral route rejects greedy sampling when temperature=0.
     * Omitting that value and supplying a neutral top_p keeps the caller's intent
     * deterministic enough while using the provider's supported sampling path. */
    protected samplingForModel(modelId: string, options?: CompletionOptions): {
        temperature: number | undefined;
        topP: number | undefined;
    };
    /**
     * OpenAI-compatible endpoints that are strict about unknown nested fields:
     * Mistral returns 422 for provider-private replay fields, Groq rejects
     * assistant `reasoning_content` with 400 (verified in production, #1070),
     * and Cerebras rejects it too — `property 'messages.N.assistant.
     * reasoning_content' is unsupported` (confirmed via vercel/ai#15042 and
     * opencode#26762, and by Cerebras' own docs, which use a `reasoning` field
     * instead). Other gateways ignore the fields, so keep the OpenAI wire
     * shape but strip our internal reasoning / thought-signature extensions
     * before sending to these platforms.
     */
    private static readonly STRICT_PLATFORMS;
    private messagesForPlatform;
    chatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): Promise<ChatCompletionResponse>;
    streamChatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): AsyncGenerator<ChatCompletionChunk>;
    /**
     * #pollinations-inband: wrap a chat stream so an in-band out-of-credits notice
     * (a 200 that streams the top-up message as content) fails over instead of
     * being shown as the answer. Only the FIRST content-bearing chunk is inspected
     * — a Pollinations credits notice arrives as a single canned message — so the
     * stream is otherwise byte-for-byte unchanged: reasoning/role chunks pass
     * straight through (first-token ttfb intact) and every chunk after the first
     * content one is untouched. Throwing on that first content chunk happens before
     * it reaches the proxy's commit point, so the fallback loop can still rotate.
     */
    private guardInBandCreditsError;
    /** This provider's OpenAI-style model catalog URL. */
    get modelsUrl(): string;
    /**
     * GET a catalog-style endpoint with this provider's auth header, extra
     * headers, proxy routing, timeout policy and quota bookkeeping. Shared by
     * validateKey (which only reads the status) and custom-endpoint model
     * discovery (#488), which also reads the body — one place owns how we talk
     * to a provider's /models route.
     *
     * Note: transport errors (DNS / timeout / TLS) propagate to the caller.
     * health.ts catches them and marks status='error' WITHOUT incrementing the
     * consecutive-failure counter — only confirmed 401/403 disables a key.
     */
    protected fetchCatalogEndpoint(url: string, apiKey: string, quotaContext?: QuotaObservationContext): Promise<Response>;
    /** The raw `${baseUrl}/models` response, body unread. Used by custom-endpoint
     *  model discovery (#488); unlike validateKey it always hits /models, never a
     *  provider-specific validateUrl, because the caller wants the catalog. */
    fetchModelCatalog(apiKey: string, quotaContext?: QuotaObservationContext): Promise<Response>;
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
//# sourceMappingURL=openai-compat.d.ts.map