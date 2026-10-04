import type { Db } from '../db/types.js';
import type { Scheduler } from '../lib/scheduler.js';
export declare const MIN_CATALOG_VERSION = "2026.06.07";
export declare const SETTING_LICENSE_KEY = "premium_license_key";
export declare const SETTING_LICENSE_STATUS = "premium_license_status";
export declare function catalogBaseUrl(): string;
export interface LicenseStatus {
    valid: boolean;
    plan: 'annual' | 'lifetime' | null;
    status: string | null;
    expiresAt: string | null;
    cancelAtPeriodEnd?: boolean;
    reason?: string;
    checkedAtMs: number;
}
interface CatalogQuirk {
    slug: string;
    title: string;
    body: string;
    severity: 'blocker' | 'warning' | 'info';
    targets: {
        platform: string | null;
        modelGlob: string | null;
    }[];
}
interface CatalogModel {
    platform: string;
    modelId: string;
    displayName: string;
    intelligenceRank: number;
    speedRank: number;
    sizeLabel: string;
    limits: {
        rpm: number | null;
        rpd: number | null;
        tpm: number | null;
        tpd: number | null;
    };
    monthlyTokenBudget: string | null;
    contextWindow: number | null;
    enabled: boolean;
    supportsVision: boolean;
    supportsTools: boolean;
    /** 'text' (default/absent) routes to the chat `models` table; 'image'/'audio'
     *  route to the separate `media_models` table. */
    modality?: string;
    /** Short display note for media models (e.g. "Keyless - up to 1024x1024"). */
    mediaNote?: string;
    /** Adapter request flavor for media rows, where one platform hosts more than
     *  one deployment style (cloudflare images: absent/'json' = JSON body,
     *  'multipart' = form-data, which the FLUX.2 family requires). Mirrors the
     *  same field on CatalogTranscriptionModel and lands in meta_json. */
    requestStyle?: string | null;
}
interface CatalogEmbedding {
    family: string;
    platform: string;
    modelId: string;
    displayName: string;
    dimensions: number;
    maxInputTokens: number | null;
    priority: number;
    enabled: boolean;
    quotaLabel: string;
}
interface CatalogTranscriptionModel {
    platform: string;
    modelId: string;
    displayName: string;
    /** Failover order within the STT chain, lower first. */
    priority: number;
    enabled: boolean;
    /** Subtitle formats the provider returns natively (e.g. ['vtt']). */
    subtitleFormats?: string[];
    /** Provider upload ceiling in bytes; absent = the route-wide 25 MB cap. */
    maxBytes?: number | null;
    /** Adapter request flavor where one platform hosts more than one deployment
     *  style (cloudflare: 'json' = base64 JSON body, 'binary' = raw bytes). */
    requestStyle?: string | null;
    /** Short display note, mirrored into media_models.quota_label. */
    quotaLabel?: string;
}
interface CatalogVideoModel {
    platform: string;
    modelId: string;
    displayName: string;
    /** Failover order within the video chain, lower first. */
    priority: number;
    enabled: boolean;
    /** Short display note, mirrored into media_models.quota_label. */
    quotaLabel?: string;
    /** Provider-native deployment id when it differs from the public model id
     *  (for example Hugging Face's fal.ai mapping). */
    providerModelId?: string;
}
interface Catalog {
    version: string;
    generatedAt: string;
    tier: 'live' | 'monthly';
    models: CatalogModel[];
    /** Optional for backward compatibility with catalogs published before the
     * embedding registry joined the signed freshness feed. */
    embeddings?: CatalogEmbedding[];
    /** Speech-to-text registry, landing in media_models with
     * modality='transcription'. Deliberately a NEW top-level key rather than
     * more `models` entries: deployed binaries that predate the transcription
     * modality would ingest unknown-modality `models` entries as CHAT models,
     * while an unknown optional key is simply ignored by their isCatalog. */
    transcriptionModels?: CatalogTranscriptionModel[];
    /** Text-to-video registry. Kept out of `models` so pre-video binaries ignore
     *  it rather than routing unknown-modality rows through chat. */
    videoModels?: CatalogVideoModel[];
    /** Platforms the catalog service manages even when this tier ships no rows
     *  for them (#1348): a provider still inside its Premium window, or one the
     *  audit deliberately keeps at zero rows. Names only, never model rows, so
     *  the monthly snapshot can carry it without leaking Premium models. Any
     *  platform listed here is off limits to built-in model discovery. Optional:
     *  older catalogs omit it and older binaries ignore it. */
    managedPlatforms?: string[];
    quirks: CatalogQuirk[];
}
export interface SyncResult {
    ok: boolean;
    action: 'applied' | 'up_to_date' | 'skipped_older' | 'error';
    version?: string;
    tier?: string;
    detail?: string;
    counts?: {
        updated: number;
        inserted: number;
        removed: number;
        skippedUnknownPlatform: number;
        quirks: number;
    };
}
/**
 * Apply a verified catalog to the local DB inside one transaction.
 *
 * Rules of engagement with user data:
 *  - metadata (name, ranks, limits, context, capabilities) tracks the catalog
 *    unless the user has an explicit local override;
 *  - catalog enabled=false force-disables (the model is dead upstream), but
 *    enabled=true never re-enables a model the user turned off themselves;
 *  - rows the user created (models.source = 'user': custom providers,
 *    declarative config, admin adds) are never updated, never deleted, and
 *    never adopted — on a platform:model_id collision the user row wins and
 *    the catalog entry is skipped outright;
 *  - catalog models the user deleted stay deleted via tombstones, while models
 *    auto-retired from an upstream 410/end-of-life response (#634) are only
 *    disabled — a catalog that still lists them lifts the retirement;
 *  - models that vanished from the catalog are deleted, exactly like the
 *    dead-model migrations do (fallback_config row first, FK order);
 *  - rows found by built-in model discovery (models.source = 'discovered',
 *    #1348) are a stopgap for platforms the catalog does not manage. The
 *    catalog outranks them: a listed platform:model_id adopts the discovered
 *    row as a catalog row, and once the catalog manages a platform at all,
 *    every other discovered row on it is retired.
 */
/** models.source for rows written by built-in model discovery (#1348). */
export declare const DISCOVERED_MODEL_SOURCE = "discovered";
/**
 * Platforms the catalog applied on this install manages (see catalogPlatforms),
 * read from the cached verified document. Empty when no catalog has been
 * applied yet. Built-in model discovery treats every platform in here as off
 * limits, so the audited catalog, not an upstream /models list, decides what
 * those providers serve.
 */
export declare function appliedCatalogPlatforms(db: Db): Set<string>;
export declare function applyCatalog(db: Db, catalog: Catalog): NonNullable<SyncResult['counts']>;
/**
 * Fetch the catalog, verify its signature, and apply it if it moves us forward.
 * `force` skips the `since` short-circuit — used right after a license key is
 * added or removed, where the tier can change without the version changing.
 */
export declare function syncCatalog(force?: boolean): Promise<SyncResult>;
/** Raw response from the catalog service's license activation endpoint. */
export interface LicenseActivation {
    valid: boolean;
    plan: string | null;
    status: string | null;
    expiresAt: string | null;
    reason?: string;
}
/**
 * Validate a key with the license service. Returns null when the service is
 * unreachable — distinguishable from a rejected key, so a transient outage can
 * be warned about instead of reported as a bad key. Shared by the dashboard's
 * POST /api/premium/key and declarative `license` config.
 */
export declare function validateLicenseKey(key: string, timeoutMs?: number): Promise<LicenseActivation | null>;
/** Revalidate the stored license against the catalog service and cache the result. */
export declare function refreshLicenseStatus(): Promise<LicenseStatus | null>;
export declare function getCachedLicenseStatus(): LicenseStatus | null;
export interface CatalogSyncState {
    baseUrl: string;
    appliedVersion: string | null;
    appliedTier: string | null;
    lastSyncMs: number | null;
    lastError: string | null;
}
export declare function getSyncState(): CatalogSyncState;
/**
 * Re-apply the cached (already signature-verified) catalog after boot.
 *
 * Migrations run on every boot and re-assert the bundled baseline — they
 * INSERT OR IGNORE baseline models the catalog may have deleted and re-run
 * the family-rule resets — while the boot-time network sync 304s on an
 * unchanged version and so would NOT re-apply. Without this step every
 * restart drifts the DB back toward the baseline until the next catalog
 * version bump. Re-applying from the local cache is synchronous, needs no
 * network, and keeps the catalog authoritative even offline.
 *
 * Legacy upgrade path: installs that applied a catalog before the cache
 * existed have an applied-version setting but no cached document. Clearing
 * the applied version makes the next poll fetch the full catalog (no `since`
 * short-circuit), which re-applies it and populates the cache.
 */
export declare function reapplyCachedCatalog(): {
    reapplied: boolean;
    version?: string;
};
export declare function startCatalogSync(scheduler: Scheduler): void;
export declare function stopCatalogSync(): void;
export {};
//# sourceMappingURL=catalog-sync.d.ts.map