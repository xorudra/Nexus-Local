import type { ChatCompletionChunk, ChatCompletionResponse } from '@freellmapi/shared/types.js';
import { BaseProvider, type KeyValidationResult } from './base.js';
export declare const SPEECHIFY_BASE_URL = "https://api.speechify.ai/v1";
export declare const SPEECHIFY_VERSION = "2026-09-08";
/** Speechify is TTS-only. Synthesis is dispatched by services/media.ts;
 * registration here provides credential management, not a fake chat API. */
export declare class SpeechifyProvider extends BaseProvider {
    readonly platform: "speechify";
    readonly name = "Speechify";
    validateKey(apiKey: string): Promise<KeyValidationResult>;
    chatCompletion(): Promise<ChatCompletionResponse>;
    streamChatCompletion(): AsyncGenerator<ChatCompletionChunk>;
}
//# sourceMappingURL=speechify.d.ts.map