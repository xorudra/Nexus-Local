export type AddressClass = 'metadata' | 'link-local' | 'loopback' | 'private' | 'public';
export declare function classifyIp(ip: string): AddressClass;
/**
 * Hostname half of {@link isLoopbackOrPrivateUrl}: true when a bare hostname
 * names THIS machine or the LAN. Callers that already parsed the URL (the
 * proxy router, which needs the hostname for NO_PROXY anyway) use this
 * directly so the URL is parsed once.
 *
 * Normalises the two spellings a URL hostname can arrive in: IPv6 literals are
 * bracketed (`[::1]`), and the FQDN form carries a trailing dot (`localhost.`
 * — a real, resolvable spelling that must not slip past as a public name).
 */
export declare function isLoopbackOrPrivateHostname(hostname: string): boolean;
/**
 * Synchronous locality check for a stored provider base_url: true when the URL
 * points at THIS machine or the LAN (loopback, RFC1918/ULA private, 'localhost').
 * Used by the rate limiter to exempt local inference servers (Ollama/llama.cpp/
 * LM Studio via the 'custom' platform) from cloud-quota cooldown ladders (#592):
 * a local box has no quota, so long benches only strand the user's one route.
 *
 * Deliberately DNS-free so it can sit on the cooldown hot path: literal IPs and
 * 'localhost'/'*.localhost' are decidable synchronously; any other hostname
 * (LAN mDNS names included) is pragmatically treated as NON-local — the worst
 * case there is the pre-existing conservative bench, never a wrong exemption.
 */
export declare function isLoopbackOrPrivateUrl(rawUrl: string | null | undefined): boolean;
export interface UrlAssessment {
    allowed: boolean;
    reason?: string;
}
export interface AssessOptions {
    resolve?: (hostname: string) => Promise<string[]>;
    blockPrivate?: boolean;
}
/**
 * Assess whether an outbound custom-provider URL is safe to contact.
 * Never throws on malformed input — a bad URL comes back as {allowed: false}.
 */
export declare function assessProviderUrl(rawUrl: string, opts?: AssessOptions): Promise<UrlAssessment>;
/**
 * Request-time enforcement: throws when the URL is blocked. Used by
 * proxyFetch for the custom platform so a base_url that slipped into the DB
 * (older install, direct DB edit, DNS change after save) still can't reach a
 * blocked address class.
 */
export declare function assertProviderUrlAllowed(rawUrl: string): Promise<void>;
//# sourceMappingURL=url-guard.d.ts.map