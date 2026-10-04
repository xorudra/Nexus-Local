import type { Db } from '../db/types.js';
/** One model to register against a custom endpoint (POST /custom body entry). */
export interface CustomModelEntry {
    modelId: string;
    displayName: string | null;
    supportsTools?: boolean;
    supportsVision?: boolean;
}
export interface RegisteredCustomModel {
    modelDbId: number;
    model: string;
    displayName: string;
    supportsTools: boolean;
    supportsVision: boolean;
    created: boolean;
}
export interface RegisterCustomModelsResult {
    keyId: number;
    /** The credential this registration bound to, for masking in responses. */
    storedKey: string;
    registered: RegisteredCustomModel[];
}
/**
 * Register (or re-register) models against a custom endpoint inside one
 * transaction.
 *
 * Key rows are matched on (base_url, secret): a new secret for a known
 * endpoint is a SECOND credential for it, not a replacement (#619), and a
 * new base_url is a separate provider (#212). Identity is per endpoint
 * (#651): the same model id on a DIFFERENT relay is a separate row with its
 * own enabled flag, ranks and stats, instead of silently rebinding the other
 * endpoint's row. A model already on THIS endpoint keeps the key it has, so
 * adding a second credential doesn't re-bind it (#619).
 *
 * Capability flags: an unset flag binds NULL so COALESCE picks the insert
 * default (tools 1, vision 0) on a new row and preserves the existing value
 * on re-registration (#470). An omitted display name binds NULL the same way
 * — it falls back to the model id on a new row and leaves a name already on
 * the row alone, so the bulk re-registration behind "Fetch models" (which
 * posts bare ids) can't wipe names the operator set.
 */
export declare function registerCustomModels(db: Db, baseUrl: string, providedKey: string | undefined, label: string | undefined, pinnedKeyId: number | undefined, entries: CustomModelEntry[]): RegisterCustomModelsResult;
/**
 * The registration loop itself, against an ALREADY-resolved endpoint key and
 * inside the caller's transaction. Split out from registerCustomModels so the
 * bulk key importer (#382) — which resolves its own key and owns a wider
 * transaction — shares this exact write path instead of keeping a second copy.
 */
export declare function registerCustomChatModels(db: Db, baseUrl: string, keyId: number, entries: CustomModelEntry[]): RegisteredCustomModel[];
//# sourceMappingURL=custom-model-register.d.ts.map