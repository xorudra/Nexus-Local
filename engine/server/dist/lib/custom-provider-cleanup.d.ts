import type { Db } from '../db/types.js';
/**
 * Drop the api_keys row(s) of a custom endpoint that nothing is registered
 * against any more, called after a custom model is deleted.
 *
 * The unit of "unused" is the ENDPOINT, not the single key. An endpoint holds a
 * pool of credentials (#619) and each model binds to just one of them, so a key
 * with nothing bound to it is usually a spare the operator added for rotation,
 * not dead weight. Reaping on the key's own count deleted such a spare as soon
 * as the model it happened to arrive with was removed (#702).
 */
export declare function deleteUnusedCustomEndpointKey(db: Db, keyId: number | null | undefined): void;
//# sourceMappingURL=custom-provider-cleanup.d.ts.map