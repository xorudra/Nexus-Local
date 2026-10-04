import type { ChatMessage, ChatCompletionResponse, ChatCompletionChunk } from '@freellmapi/shared/types.js';
import { BaseProvider, type CompletionOptions, type KeyValidationResult } from './base.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
export { sanitizeForGemini } from '../lib/gemini-wire.js';
/**
 * Extended generationConfig knobs translated from the OpenAI wire: topK,
 * seed, penalties, and structured output. JSON output conflicts with function
 * calling on Gemini ("Function calling with a response mime type:
 * 'application/json' is unsupported"), so response_format is only applied on
 * tool-free requests. Params Gemini has no equivalent for (min_p, logit_bias,
 * logprobs…) are dropped by the platform policy in lib/sampling-params.ts and
 * are ignored here. Exported for tests.
 */
export declare function toGeminiExtendedConfig(options?: CompletionOptions): Record<string, unknown>;
export interface GoogleProviderOptions {
    /** Per-provider HTTP timeout override. Some Gemini models (notably
     *  Gemma reasoning variants) take 20-60s on cold start; the OpenAI-compat
     *  default of 15s false-flags them as broken. Mirrors OpenAICompatProvider. */
    timeoutMs?: number;
}
export declare class GoogleProvider extends BaseProvider {
    readonly platform: "google";
    readonly name = "Google AI Studio";
    private readonly timeoutMs;
    constructor(opts?: GoogleProviderOptions);
    chatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): Promise<ChatCompletionResponse>;
    streamChatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): AsyncGenerator<ChatCompletionChunk>;
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
//# sourceMappingURL=google.d.ts.map