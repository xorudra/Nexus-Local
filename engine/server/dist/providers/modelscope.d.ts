import { OpenAICompatProvider } from './openai-compat.js';
import type { KeyValidationResult } from './base.js';
import { type QuotaObservationContext } from '../services/provider-quota.js';
/**
 * ModelScope (魔搭社区, Alibaba) — OpenAI-compatible inference API.
 *
 * Everything except key validation is stock OpenAI-compat. validateKey is
 * overridden because of a trap in ModelScope's API surface:
 *
 *   GET /v1/models returns 200 WITHOUT auth — and, verified keyless on
 *   2026-07-26, it also returns 200 with a GARBAGE Bearer token. The default
 *   openai-compat validateKey (GET /v1/models with the key) would therefore
 *   mark any invalid key healthy forever. /v1/models is useless for
 *   validation on this platform.
 *
 * The only endpoint verified to enforce auth is POST /v1/chat/completions:
 * a garbage token gets a clean
 *   401 {"error":{"message":"Authentication failed, please make sure that a
 *        valid ModelScope token is supplied."}}
 * before any generation happens. So validation makes a 1-token chat
 * completion. The model id is picked dynamically from GET /v1/models (first
 * entry) because the roster churns — a hardcoded id would rot.
 *
 * COST: a successful validation burns 1 paid 1-token completion per health
 * check against the account's magic-grain (魔粒) quota — observed as 2 魔粒
 * per ultra-tier request (2026-08-14), not the historical 2000-requests/day
 * free API quota. With the default 5-minute health pass that would be ~288
 * paid probes per key per day. A successful validation is therefore cached
 * per key for MODELSCOPE_VALIDATE_CACHE_MS (default 24h) — repeat health
 * passes return true without re-probing, taking the steady-state cost to one
 * probe per key per day. A failed-auth validation is rejected before
 * generation and, per maintainer reports, does not count against quota.
 *
 * Community testers must confirm (we have NO real token for this platform):
 * the maintainer-documented bad-binding failure is
 *   `401 please bind your alibaba cloud account before use`
 * — a token minted without binding the ModelScope account to an Alibaba
 * Cloud CHINA-site account fails every call with that message. It flows
 * through validationResult() into the health error verbatim so users see the
 * actionable reason instead of a generic "invalid key". See issue #581.
 */
export declare class ModelScopeProvider extends OpenAICompatProvider {
    /** key-material fingerprint → last successful validation wall-clock (ms).
     *  Keyed on the token itself, not the row id, so editing a key in place
     *  re-probes instead of inheriting the old token's verdict. */
    private readonly lastValidatedAt;
    constructor();
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
//# sourceMappingURL=modelscope.d.ts.map