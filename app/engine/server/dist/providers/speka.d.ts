import { type KeyValidationResult } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
export declare const SPEKA_BASE_URL = "https://speka.me/v1";
/** OpenAI-compatible chat; model rows are delivered only by the signed catalog.
 * Free's $1/month is shared across chat and embeddings, not a per-model grant.
 * Docs: https://speka.me/docs and https://speka.me/pricing. */
export declare class SpekaProvider extends OpenAICompatProvider {
    constructor();
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
//# sourceMappingURL=speka.d.ts.map