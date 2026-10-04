import type { ChatCompletionChunk, ChatCompletionResponse, ChatMessage, Platform } from '@freellmapi/shared/types.js';
import { BaseProvider, type CompletionOptions, type KeyValidationResult } from './base.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
/** ACLIDE exposes Responses, NOT Chat Completions. Streaming clients receive
 * buffered compatibility chunks after a terminal response, as with Sail.
 * No model rows are seeded here: the signed catalog owns the release gate. */
export declare class AclideProvider extends BaseProvider {
    readonly platform: Platform;
    readonly name = "ACLIDE";
    private headers;
    private input;
    private body;
    private record;
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
    chatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): Promise<ChatCompletionResponse>;
    streamChatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): AsyncGenerator<ChatCompletionChunk>;
}
//# sourceMappingURL=aclide.d.ts.map