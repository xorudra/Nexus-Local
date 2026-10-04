import type { Db } from '../db/types.js';
export type CustomMediaModality = 'image' | 'audio' | 'transcription';
export interface CustomMediaEntry {
    modelId: string;
    displayName: string | null;
    modality: CustomMediaModality;
    quotaLabel?: string;
}
export interface RegisteredCustomMediaModel {
    modelDbId: number;
    model: string;
    modality: CustomMediaModality;
    created: boolean;
}
/**
 * Upsert one media model row against an ALREADY-resolved endpoint key, inside
 * the caller's transaction. media_models identity is (platform, model_id) with
 * no endpoint_scope — a model already on this endpoint keeps the key it has;
 * only a move to a different endpoint re-binds it (#619 semantics).
 */
export declare function registerCustomMediaModel(db: Db, keyId: number, entry: CustomMediaEntry): RegisteredCustomMediaModel;
//# sourceMappingURL=custom-media-register.d.ts.map