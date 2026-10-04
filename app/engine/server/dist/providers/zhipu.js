import { OpenAICompatProvider } from './openai-compat.js';
/** Domestic console (bigmodel.cn) — the historical registration default. */
const DOMESTIC_BASE_URL = 'https://open.bigmodel.cn/api/paas/v4';
/** Global console (z.ai). Same OpenAI-compatible surface, different key namespace. */
const GLOBAL_BASE_URL = 'https://api.z.ai/api/paas/v4';
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
export class ZhipuProvider extends OpenAICompatProvider {
    /**
     * Keys proven to belong to the global console. Deliberately in-memory: it is
     * a cache of something validateKey can always re-derive, and health checks
     * re-run validateKey, so a restart costs one extra probe per global key and
     * nothing else. Everything absent from this set uses the domestic host.
     */
    globalKeys = new Set();
    constructor(opts = {}) {
        super({
            platform: 'zhipu',
            name: 'Zhipu AI',
            baseUrl: DOMESTIC_BASE_URL,
            timeoutMs: opts.timeoutMs,
        });
    }
    /**
     * Recover the bearer from a request this provider built. OpenAICompatProvider
     * composes every URL from its own private base URL, so this is the only place
     * where the outgoing URL and the key that should choose it are both in scope.
     */
    static apiKeyOf(init) {
        const raw = init.headers;
        const auth = raw instanceof Headers
            ? raw.get('authorization')
            : raw?.['Authorization']
                ?? raw?.['authorization'];
        return auth?.startsWith('Bearer ') ? auth.slice('Bearer '.length) : undefined;
    }
    /**
     * Swap the pinned domestic host for the global one when this key validated
     * there. A URL that already names a host explicitly — the validateKey probes
     * below — is left alone, which keeps validation free of its own cache.
     */
    resolveUrl(url, init) {
        if (!url.startsWith(DOMESTIC_BASE_URL))
            return url;
        const apiKey = ZhipuProvider.apiKeyOf(init);
        if (!apiKey || !this.globalKeys.has(apiKey))
            return url;
        return GLOBAL_BASE_URL + url.slice(DOMESTIC_BASE_URL.length);
    }
    fetchWithTimeout(url, init, timeoutMs, fetchOpts) {
        return super.fetchWithTimeout(this.resolveUrl(url, init), init, timeoutMs, fetchOpts);
    }
    async validateKey(apiKey, quotaContext) {
        // Drop any earlier verdict first: a re-check must start from the domestic
        // default (a key can be replaced in place), and it keeps resolveUrl from
        // rewriting the domestic probe below.
        this.globalKeys.delete(apiKey);
        const domesticRes = await this.fetchCatalogEndpoint(`${DOMESTIC_BASE_URL}/models`, apiKey, quotaContext);
        if (domesticRes.status !== 401 && domesticRes.status !== 403) {
            return this.validationResult(domesticRes);
        }
        // Only reached when the domestic host said "not my key" — which is exactly
        // what it says about a valid global-console key. Ask the global host before
        // calling the key invalid.
        let globalRes;
        try {
            globalRes = await this.fetchCatalogEndpoint(`${GLOBAL_BASE_URL}/models`, apiKey, quotaContext);
        }
        catch {
            // api.z.ai unreachable (no route, blocked, timeout). Nothing new learned,
            // so report the domestic rejection rather than turning a plainly invalid
            // key into a transport error that health.ts would log as 'error'.
            return this.validationResult(domesticRes);
        }
        if (globalRes.status !== 401 && globalRes.status !== 403) {
            this.globalKeys.add(apiKey);
            return this.validationResult(globalRes);
        }
        // Rejected by both consoles. Report the domestic failure: that is the host
        // the key is used against by default, so its message is the relevant one.
        return this.validationResult(domesticRes);
    }
}
//# sourceMappingURL=zhipu.js.map