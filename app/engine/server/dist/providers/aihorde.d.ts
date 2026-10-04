import type { ChatMessage, ChatCompletionResponse, ChatCompletionChunk, Platform } from '@freellmapi/shared/types.js';
import { BaseProvider, type CompletionOptions, type KeyValidationResult } from './base.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
export declare class AIHordeProvider extends BaseProvider {
    readonly platform: Platform;
    readonly name = "AI Horde";
    /** Works out of the box via the anonymous key: the gateway stores a sentinel
     * row (so routing treats the platform as configured) and we send the anon
     * bearer. A stored real horde key replaces the sentinel for higher priority. */
    keyless: boolean;
    private readonly baseUrl;
    /** Map the stored credential to the bearer we send upstream. The keyless flow
     * stores `'no-key'` (or nothing) for the anonymous case → send AI Horde's
     * documented anonymous key. Any other stored value is treated as a registered
     * key and forwarded verbatim for higher queue priority. */
    private resolveBearer;
    /** Build the upstream body, normalizing the OpenAI params the proxy rejects
     * (see class doc). No `stream` — we never stream upstream. */
    private buildBody;
    /** Replace the proxy's `{"kudos": N}` usage with synthesized token counts so
     * downstream analytics aren't all zero. Prompt from the input messages,
     * completion from the returned content. */
    private synthesizeUsage;
    private parseError;
    chatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): Promise<ChatCompletionResponse>;
    /**
     * AI Horde's proxy returns a queued generation as one response, so there is no
     * meaningful token-by-token stream. We run the same blocking call and emit the
     * result as a minimal SSE sequence (role → content → finish) so streaming
     * clients still work.
     */
    streamChatCompletion(apiKey: string, messages: ChatMessage[], modelId: string, options?: CompletionOptions, quotaContext?: QuotaObservationContext): AsyncGenerator<ChatCompletionChunk>;
    /**
     * The OpenAI proxy's GET /v1/models answers 200 for ANY bearer (it does not
     * validate the key), and the anonymous key is always usable, so a reachable
     * endpoint means the platform is healthy. Mirrors keyless providers: only a
     * confirmed 401/403 is treated as an invalid key. Transport errors propagate
     * to health.ts (marked status='error' without counting a failure).
     */
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
//# sourceMappingURL=aihorde.d.ts.map