import { OpenAICompatProvider } from './openai-compat.js';
import type { KeyValidationResult, ProviderFetchOptions } from './base.js';
import type { QuotaObservationContext } from '../services/provider-quota.js';
/**
 * Zhipu AI / Z.ai. One platform, two consoles that do NOT share a key
 * namespace: a key minted on z.ai is a 401 at open.bigmodel.cn and vice versa.
 * Pinning the platform to the domestic host therefore made every global-console
 * key look like a bad key, with a 401 that says nothing about which host it
 * came from.
 *
 * So the domestic host stays the default — an existing bigmodel.cn deployment
 * behaves exactly as before, one request, same URL — and only a key the
 * domestic host actually REJECTS is re-probed against the global host during
 * validation. The verdict is remembered per key so the key's chat, streaming
 * and catalog traffic follows it.
 */
export declare class ZhipuProvider extends OpenAICompatProvider {
    /**
     * Keys proven to belong to the global console. Deliberately in-memory: it is
     * a cache of something validateKey can always re-derive, and health checks
     * re-run validateKey, so a restart costs one extra probe per global key and
     * nothing else. Everything absent from this set uses the domestic host.
     */
    private readonly globalKeys;
    constructor(opts?: {
        timeoutMs?: number;
    });
    /**
     * Recover the bearer from a request this provider built. OpenAICompatProvider
     * composes every URL from its own private base URL, so this is the only place
     * where the outgoing URL and the key that should choose it are both in scope.
     */
    private static apiKeyOf;
    /**
     * Swap the pinned domestic host for the global one when this key validated
     * there. A URL that already names a host explicitly — the validateKey probes
     * below — is left alone, which keeps validation free of its own cache.
     */
    private resolveUrl;
    protected fetchWithTimeout(url: string, init: RequestInit, timeoutMs?: number, fetchOpts?: ProviderFetchOptions): Promise<Response>;
    validateKey(apiKey: string, quotaContext?: QuotaObservationContext): Promise<KeyValidationResult>;
}
//# sourceMappingURL=zhipu.d.ts.map