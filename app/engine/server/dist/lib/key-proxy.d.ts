/**
 * Per-key proxy override (#590) — storage and presentation helpers.
 *
 * A proxy URL routinely carries `user:pass@` credentials, so it is stored the
 * same way the API key on that row is: AES-256-GCM ciphertext + iv + auth tag
 * (see the 20260810_000001_api_key_proxy migration). Everything outside the DB
 * layer speaks in plain strings, with '' meaning "no override".
 */
/** The three columns that hold a key's encrypted proxy URL. */
export interface EncryptedProxyColumns {
    proxy_encrypted: string | null;
    proxy_iv: string | null;
    proxy_auth_tag: string | null;
}
export declare const KEY_PROXY_URL_ERROR = "proxyUrl must be a valid proxy URL using http, https, socks4, socks4a, socks5 or socks5h (e.g. socks5://user:pass@host:1080), or '' to clear it";
/** Longest proxy URL accepted — generous for credentials, bounded for the DB. */
export declare const KEY_PROXY_URL_MAX = 2048;
/**
 * True when `url` is storable as a per-key override: either '' (no override)
 * or a parseable URL on one of the schemes the proxy layer can dispatch
 * through. Deliberately the SAME scheme list the global proxy validator uses
 * (routes/settings.ts), so a URL that works globally works per-key.
 */
export declare function isValidKeyProxyUrl(url: string): boolean;
/**
 * Encrypt a per-key proxy URL for storage. '' (or whitespace) clears the
 * override, which is all three columns NULL.
 */
export declare function encryptProxyUrl(url: string): {
    encrypted: string | null;
    iv: string | null;
    authTag: string | null;
};
/**
 * Read a per-key proxy URL back off a row. Returns '' for "no override" and
 * also for a row that cannot be decrypted (a DB carried over to a different
 * ENCRYPTION_KEY): a failed decrypt must degrade to the global proxy, never
 * take the request down — the key itself fails loudly on the same row anyway.
 */
export declare function decryptProxyUrl(row: Partial<EncryptedProxyColumns> | undefined | null): string;
/**
 * Render a proxy URL for the dashboard with any embedded password removed —
 * the counterpart of maskKey() for this field. The username stays visible
 * (it identifies the account without being the secret):
 *   socks5://alice:hunter2@proxy.internal:1080 → socks5://alice:***@proxy.internal:1080
 * '' stays ''.
 */
export declare function maskProxyUrl(url: string): string;
//# sourceMappingURL=key-proxy.d.ts.map