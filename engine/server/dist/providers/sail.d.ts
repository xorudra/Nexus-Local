import type { ChatCompletionChunk, ChatCompletionResponse, ChatMessage, Platform } from '@freellmapi/shared/types.js';
import { BaseProvider, type CompletionOptions, type KeyValidationResult } from './base.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
interface SailProviderOptions {
    timeoutMs?: number;
    pollIntervalMs?: number;
}
/**
 * Sail Research adapter.
 *
 * Sail's stable surface is the OpenAI Responses API, not streaming Chat
 * Completions. Every request is submitted with `background: true`, then polled
 * until terminal. That is required for its flex-only models and avoids proxy
 * timeouts for core models that spend several minutes queued. The completed
 * Responses object is normalized back into FreeLLMAPI's Chat Completions shape;
 * streaming callers receive a small synthesized role/content/finish sequence.
 */
export declare class SailProvider extends BaseProvider {
    readonly platform: Platform;
    readonly name = "Sail Research";
    private readonly timeoutMs;
    private readonly pollIntervalMs;
    constructor(options?: SailProviderOptions);
    private authHeaders;
    private completionWindow;
    private reasoningEffort;
    /** Translate Chat Completions history into Responses input items. */
    private inputItems;
    private toolChoice;
    private textFormat;
    private buildBody;
    private errorText;
    private recordQuota;
    private parseResponse;
    private wait;
    private runResponse;
    private usageOf;
    private normalize;
    chatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): Promise<ChatCompletionResponse>;
    streamChatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): AsyncGenerator<ChatCompletionChunk>;
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
export {};
//# sourceMappingURL=sail.d.ts.map