import type { KeyValidationResult } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
/** Router9's public /models returns 200 even for a bogus key. Authenticate
 * with a deliberately incomplete chat request instead: no model or prompt
 * can reach inference. Verified 2026-09-10: invalid keys get 401; a valid key
 * gets 404 model_not_found PLUS account credit headers. This consumes one
 * request from the provider's burst allowance, but no inference credits.
 *
 * The inherited adapter already splits inline <think> blocks and accepts
 * streams ending at EOF after finish_reason (Router9 omits [DONE]). */
export declare class Router9Provider extends OpenAICompatProvider {
    constructor();
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
//# sourceMappingURL=router9.d.ts.map