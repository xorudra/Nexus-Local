/** The sentinel the Keys page stores for key-optional platforms and auth-off
 * custom endpoints (routes/keys.ts keeps `no-key`), plus the empty string a
 * caller can hand a provider when no credential exists. Anything else is a
 * real key (#1331). */
export declare const NO_KEY_SENTINEL = "no-key";
export declare function isAnonymousCredential(apiKey: string | null | undefined): boolean;
/** `Authorization: Bearer <key>` for a real key, nothing for the sentinel:
 * upstreams read `Bearer no-key` as an invalid key, so anonymous calls must
 * omit the header entirely (#1331). */
export declare function bearerAuthHeader(apiKey: string | null | undefined): Record<string, string>;
//# sourceMappingURL=credential.d.ts.map