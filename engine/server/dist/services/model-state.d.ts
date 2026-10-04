import type { Db } from '../db/types.js';
export type CatalogModelKind = 'chat' | 'media';
export interface ModelOverridePatch {
    displayName?: string;
    intelligenceRank?: number;
    speedRank?: number;
    sizeLabel?: string;
    rpmLimit?: number | null;
    rpdLimit?: number | null;
    tpmLimit?: number | null;
    tpdLimit?: number | null;
    monthlyTokenBudget?: string;
    contextWindow?: number | null;
    supportsVision?: boolean;
    supportsTools?: boolean;
    enabled?: boolean;
}
type StoredOverrides = Partial<ModelOverridePatch>;
export declare function routableContextWindow(platform: string, modelId: string, contextWindow: number | null): number | null;
/** Called after catalog metadata is written, before local overrides are applied. */
export declare function refreshModelOverrideBaselines(db: Db, platform: string, modelId: string): void;
/**
 * The fields a stored overrides blob actually overrides, for callers that
 * already selected `model_overrides.overrides_json` alongside the model row.
 * The dashboard uses this to mark individual inputs as locally overridden
 * instead of flagging the whole model (#551).
 */
export declare function overriddenFieldNames(overridesJson: string | null | undefined): Array<keyof ModelOverridePatch>;
export declare function isCatalogManagedModel(row: {
    platform: string;
    key_id?: number | null;
    source?: string;
}): boolean;
export type CatalogTombstoneSource = 'user' | 'upstream_eol';
export interface CatalogModelTombstone {
    source: CatalogTombstoneSource;
    reason: string | null;
    createdAt: string;
}
export declare function getCatalogModelTombstone(db: Db, kind: CatalogModelKind, platform: string, modelId: string): CatalogModelTombstone | undefined;
/**
 * True only for models the USER deleted — the "keep it deleted" contract every
 * caller here means. An upstream-retirement tombstone deliberately does NOT
 * count: those models stay in the catalog's write path so a refreshed catalog
 * can reinstate them (see reinstateUpstreamRetiredCatalogModel).
 */
export declare function isCatalogModelTombstoned(db: Db, kind: CatalogModelKind, platform: string, modelId: string): boolean;
export declare function recordCatalogModelTombstone(db: Db, kind: CatalogModelKind, platform: string, modelId: string, options?: {
    source?: CatalogTombstoneSource;
    reason?: string | null;
}): void;
/**
 * Auto-disable a catalog model the provider reports as permanently retired
 * (issue #634). Deliberately NOT a delete: the row stays visible in the
 * dashboard, tagged with the upstream wording, and the user can flip it back on
 * if they disagree. Turning off the chain entries (and the active profile's
 * copy) is exactly what the dashboard's own switch does, so the router stops
 * picking it while an explicitly-requested model id still resolves.
 *
 * Returns true when this call performed the retirement (false when it was
 * already retired, or the user had deleted the model outright).
 */
export declare function retireCatalogModelUpstream(db: Db, modelDbId: number, platform: string, modelId: string, reason: string): boolean;
/**
 * Lift an upstream retirement: a catalog that still lists the model — and lists
 * it enabled — is newer and better evidence than one provider's 404. Returns
 * true when a retirement was actually lifted.
 */
export declare function reinstateUpstreamRetiredCatalogModel(db: Db, platform: string, modelId: string): boolean;
export declare function clearCatalogModelTombstone(db: Db, kind: CatalogModelKind, platform: string, modelId: string): void;
export declare function upsertModelOverrides(db: Db, platform: string, modelId: string, patch: ModelOverridePatch, options?: {
    baselineRow?: Record<string, unknown>;
}): StoredOverrides;
export declare function getModelOverrides(db: Db, platform: string, modelId: string): StoredOverrides;
/**
 * Every model whose stored overrides pin ONE given field, as a set of
 * "platform:model_id" keys. One query over a table that only ever holds the
 * models a user has actually touched, so callers that need "is this field
 * user-owned?" for a whole catalog don't do it per model.
 *
 * Note it keys off the field, not the row: a user who renamed a model has an
 * override row but has said nothing about its speed_rank, so a derived value
 * may still fill that column (#619).
 */
export declare function modelsWithOverriddenField(db: Db, field: keyof ModelOverridePatch): Set<string>;
export declare function applyModelOverrides(db: Db, platform: string, modelId: string): boolean;
export declare function applyAllModelOverrides(db: Db): number;
export declare function deleteTombstonedCatalogModels(db: Db): number;
export {};
//# sourceMappingURL=model-state.d.ts.map