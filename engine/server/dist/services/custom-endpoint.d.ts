import type { Db } from '../db/types.js';
export interface ResolvedEndpointKey {
    keyId: number;
    /** Plaintext of the key now bound to this endpoint — for masking in responses. */
    storedKey: string;
    /** True when this call added a credential rather than updating one. */
    created: boolean;
}
/**
 * Resolve the api_keys row a custom-endpoint registration should bind to,
 * creating or updating it as needed. Never destroys a stored credential:
 *  - no key submitted        → reuse the endpoint's first key (label refresh only)
 *  - a key already on record  → update that row (label / re-enable)
 *  - a new key, placeholder-only endpoint → replace the placeholder in place
 *  - a new key, endpoint already has one → INSERT a second credential (#619)
 *
 * `pinnedKeyId` lets a caller that already knows WHICH credential of the pool
 * it is acting for name it — the bulk registration of discovered models (#488)
 * comes back holding the key row the user fetched the list with. It only
 * applies when that row really serves this base_url and no new secret was
 * submitted; a new secret still goes through the rules above.
 */
export declare function resolveCustomEndpointKey(db: Db, baseUrl: string, providedKey: string | undefined, label: string | undefined, pinnedKeyId?: number): ResolvedEndpointKey;
/** True when this endpoint already stores this exact secret. Lets a caller tell
 *  a genuinely new credential from a re-submit of one already in the pool, which
 *  `resolveCustomEndpointKey` deliberately treats the same way. */
export declare function endpointHasCredential(db: Db, baseUrl: string, secret: string): boolean;
/**
 * Every api_keys id that serves the SAME custom endpoint as `keyId` — i.e. the
 * credential pool a model bound to `keyId` may rotate across. Falls back to the
 * key itself when the row is gone or carries no base_url.
 */
export declare function customEndpointKeyIds(db: Db, keyId: number): Set<number>;
/**
 * The other key still serving this endpoint once `keyId` is gone, or null when
 * it was the last one. Used to re-home an endpoint's models instead of deleting
 * them with the key.
 */
export declare function siblingEndpointKeyId(db: Db, keyId: number, baseUrl: string | null): number | null;
export interface CustomEndpointCredential {
    keyId: number;
    baseUrl: string;
    /** Decrypted secret, or null when the row's ciphertext cannot be decrypted. */
    apiKey: string | null;
}
/**
 * Every ENABLED custom endpoint, one entry per distinct base_url, carrying its
 * first stored credential. Used by the scheduled model sync (#674/#663/#656)
 * to refresh model lists unattended: the manual route asks the operator for a
 * key mid-typing, but a scheduled pass can only use what the endpoint already
 * has on record.
 *
 * Disabled keys are excluded: turning an endpoint off means "stop using this",
 * so an unattended pass must not keep polling it and registering new (enabled)
 * model rows behind the operator's back.
 */
export declare function listCustomEndpoints(db: Db): CustomEndpointCredential[];
//# sourceMappingURL=custom-endpoint.d.ts.map