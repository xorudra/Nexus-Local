import type { ChatCompletionChunk, ChatCompletionResponse, ChatMessage, Platform } from '@freellmapi/shared/types.js';
import { BaseProvider, type CompletionOptions, type KeyValidationResult } from './base.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
/** Hosted BYOK API, not self-hosted weights. Model rows belong exclusively in
 * the signed catalog to preserve Premium-now / Free-after-30-days delivery. */
export declare class MoondreamProvider extends BaseProvider {
    readonly platform: Platform;
    readonly name = "Moondream";
    private headers;
    private body;
    private record;
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
    private request;
    chatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): Promise<ChatCompletionResponse>;
    streamChatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): AsyncGenerator<ChatCompletionChunk>;
}
//# sourceMappingURL=moondream.d.ts.map