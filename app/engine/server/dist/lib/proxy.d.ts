import type { ProxyMode } from '@freellmapi/shared/types.js';
/** Run `fn` with a per-key proxy override in effect; empty URL = global proxy. */
export declare function withKeyProxy<T>(proxyUrl: string | undefined, fn: () => T): T;
/** Every proxy scheme the app accepts. Shared with the settings validator. */
export declare const PROXY_SCHEMES: readonly string[];
export declare const PROXY_MODES: readonly ProxyMode[];
export declare const FETCH_RELAY_TARGET_HEADER = "fetch-relay-target";
export declare const FETCH_RELAY_AUTH_HEADER = "fetch-relay-authorization";
/** True for a hostname that cannot leave the local machine. `new URL()` keeps
 *  the brackets on an IPv6 literal, hence both spellings of ::1. */
export declare function isLoopbackRelayHostname(hostname: string): boolean;
/** Why a URL cannot serve as a Fetch Relay endpoint, or undefined when it can.
 *  Shared by the settings validator and the boot-time env guard so the
 *  dashboard and a headless install agree on what a usable relay looks like. */
export declare function fetchRelayUrlError(url: string): string | undefined;
/** True when the URL names a SOCKS scheme (so it needs SocksProxyAgent, not undici). */
export declare function isSocksProxyUrl(url: string): boolean;
/**
 * Read the OS-wide proxy configuration. Synchronous and best-effort: never
 * throws, returns '' when the platform is unsupported or the command fails.
 *
 * - macOS: `scutil --proxy` (System Settings → Network → Proxies)
 * - Windows: Internet Options registry (ProxyEnable + ProxyServer)
 * - Linux: GNOME gsettings (the most common desktop), manual mode only
 */
export declare function detectSystemProxy(): {
    url: string;
    source: string;
};
/** Parse `scutil --proxy` output: HTTPEnable/HTTPProxy/HTTPPort first, then SOCKS. */
export declare function parseScutilProxy(out: string): {
    url: string;
    source: string;
};
/** Parse Windows registry output; ProxyServer may be "host:port" or "http=…;https=…". */
export declare function parseRegProxy(enableOut: string, serverOut: string): {
    url: string;
    source: string;
};
/** Called once at startup (after initDb) and on PUT /api/settings/proxy. */
export declare function applyProxyUrl(dbValue: string): void;
/**
 * Hydrate the process-wide proxy state from the settings table.
 *
 * The standalone server does this in index.ts after initDb; the desktop
 * embedder (desktop/src/server-host.ts) builds the app without index.ts and
 * must call this itself — otherwise the URL saved by PUT /api/settings/proxy
 * sits in the DB but the process starts with an empty proxy and every
 * outbound request goes direct until the user re-saves the setting (#949).
 * Safe to call more than once; it is idempotent.
 */
export declare function restoreProxySettings(): void;
export declare function getProxyUrl(): string;
/** Set how the global proxy URL is used. An explicit PROXY_MODE wins. A legacy
 * PROXY_URL (or an ambient standard proxy variable) without PROXY_MODE always
 * stays a forward proxy, regardless of a saved dashboard mode. */
export declare function applyProxyMode(dbValue: string): void;
export declare function getProxyMode(): ProxyMode;
/** Set the bearer token used only to authenticate FreeLLMAPI to a Fetch Relay.
 * The environment wins so headless deployments never expose or overwrite it
 * through the dashboard. This token is separate from the provider's
 * Authorization header, which is preserved for the upstream request. */
export declare function applyFetchRelayToken(dbValue: string): void;
export declare function getFetchRelayToken(): string;
/** Encrypt the dashboard-saved Relay credential at rest. The environment form
 * never enters the database. */
export declare function encodeFetchRelayToken(value: string): string;
/** Toggle the proxy on/off without losing the URL. */
export declare function applyProxyEnabled(enabled: boolean): void;
export declare function isProxyEnabled(): boolean;
/** Set which platforms bypass the proxy. Comma-separated string from DB. */
export declare function applyProxyBypass(platformsCsv: string): void;
export declare function getProxyBypassPlatforms(): string[];
/** The NO_PROXY rules currently in effect (parsed from the env at apply time). */
export declare function getNoProxyRules(): string[];
/**
 * Request kinds recognised in AbortError messages. Mirrors the values
 * written to `requests.request_type` so the abort message and the row
 * column agree on terminology.
 */
export type ProxyRequestType = 'chat' | 'embedding' | 'image' | 'video' | 'audio' | 'transcription' | 'unknown';
/**
 * Format the `<platform>, <type>, <timeout>s` tag. Exposed for testing and
 * for callers that want to log the tag without re-throwing. Falls back
 * gracefully when fields are missing: unknown platform → 'unknown',
 * unknown type → 'unknown', no timeout → omit the trailing ', <N>s'.
 */
export declare function describeAbort(platform: string | undefined, type: ProxyRequestType, timeoutMs: number | undefined): string;
/**
 * DNS `lookup` override for the SOCKS fallback path: hand back the hostname it
 * was asked to resolve, unchanged.
 *
 * socks-proxy-agent resolves the DESTINATION locally for the `socks5://` and
 * `socks4://` schemes (`shouldLookup`) and sends the proxy a bare IP; only
 * `socks5h://`/`socks4a://` pass the name through. That local resolution is
 * what breaks rule-based proxy clients (Clash and friends), which match routing
 * rules on the domain and have nothing to match once the name is gone — and on
 * a DNS-poisoned network it resolves to the poisoned address as well.
 *
 * `http.request` forwards this to the agent as `opts.lookup`, so echoing the
 * hostname makes every SOCKS scheme reach the proxy with the domain intact,
 * i.e. behave like its `h`/`a` variant. The agent only forwards the "address"
 * as the SOCKS destination host — it never inspects the address family, so the
 * `4` is a placeholder the callback signature requires.
 */
export declare function socksHostnameLookup(hostname: string, _options: unknown, callback: (err: null, address: string, family: number) => void): void;
export declare function proxyFetch(url: string, init?: RequestInit, platform?: string, requestType?: ProxyRequestType, timeoutMs?: number): Promise<Response>;
/**
 * Returns true when the proxy is configured AND enabled. Used by the dashboard
 * to show the "Active" badge. Intentionally does NOT construct a dispatcher (so
 * it never triggers the lazy undici import) — "configured + enabled" is exactly
 * what the badge means.
 */
export declare function isProxyActive(): boolean;
/** Force-rebuild the outbound connection pools on the next request. Called on
 *  sleep/wake recovery to drop pooled TCP connections that died while the
 *  host was suspended (undici keeps them warm and would hand a dead socket
 *  to the first post-wake request). */
export declare function flushProxyCache(): void;
export interface ProxyProbeResult {
    ok: boolean;
    latencyMs: number;
    status?: number;
    error?: string;
    /** The URL the probe actually called, so the dashboard can say what it
     *  reached rather than leaving the operator to guess. */
    target?: string;
}
/**
 * Where the probe goes when the caller names no target and no provider key
 * can supply one.
 *
 * Deliberately NOT an AI vendor. The probe answers "can this proxy reach the
 * internet", and pointing it at a third party the install may never use makes
 * the test lie in both directions: a gateway that never calls that vendor now
 * calls it on every Test, and a network that blocks it reports a working proxy
 * as broken. `/cdn-cgi/trace` is a plain-text reachability endpoint with no
 * account, no rate limit and no regional AI-vendor blocking.
 */
export declare const DEFAULT_PROXY_PROBE_TARGET = "https://www.cloudflare.com/cdn-cgi/trace";
/**
 * Test whether a proxy URL can actually route traffic (#863). Backs the
 * Settings → Outbound proxy "Test" button so an operator can verify a draft
 * value BEFORE saving it.
 *
 * `proxyUrl` empty → falls back to the saved global proxy URL (getProxyUrl);
 * when neither is set the probe runs direct, so the button is still useful
 * before any proxy has been configured.
 *
 * The probe target is supplied by the caller and should be an endpoint this
 * install genuinely uses — the /models route of a provider the operator holds
 * an enabled key for. Any HTTP response, even a 401/403 without a key, proves
 * the proxy route works; only a network-level failure (DNS, connect, timeout)
 * counts as a proxy failure.
 */
export declare function probeProxyUrl(proxyUrl: string | undefined, options?: {
    targetUrl?: string;
    timeoutMs?: number;
    mode?: ProxyMode;
    relayToken?: string;
}): Promise<ProxyProbeResult>;
//# sourceMappingURL=proxy.d.ts.map