import type { Db } from '../db/types.js';
import type { Scheduler } from '../lib/scheduler.js';
import type { Platform } from '@freellmapi/shared/types.js';
import { OpenAICompatProvider } from '../providers/openai-compat.js';
import { type DiscoveredModel } from './model-discovery.js';
/** Built-in platforms eligible for discovery. Each is OpenAI-compatible and has
 *  zero rows, enabled or disabled, in the signed live catalog (checked against
 *  2026.09.27). Remove a platform here in the same change that adds it to the
 *  catalog; managedPlatforms in the catalog covers binaries already shipped. */
export declare const BUILTIN_DISCOVERY_PLATFORMS: readonly Platform[];
/** `BUILTIN_MODEL_DISCOVERY`: 'manual' (default) keeps only the dashboard's
 *  Fetch models action, so nothing is registered without the operator picking
 *  it; 'auto' also discovers on key save, after a healthy check and on the
 *  custom-model sync cadence; 'off' disables both. Manual is the default
 *  because these providers bill funded accounts (SiliconFlow, LongCat) and
 *  label paid models inconsistently, so an automatic pass could route traffic
 *  to models that cost money. */
export type BuiltinDiscoveryMode = 'auto' | 'manual' | 'off';
export declare function builtinDiscoveryMode(): BuiltinDiscoveryMode;
export type IneligibleReason = 'disabled' | 'not_allowlisted' | 'not_openai_compatible' | 'catalog_managed';
export interface DiscoveryEligibility {
    eligible: boolean;
    reason?: IneligibleReason;
    /** The registered adapter, when eligible. */
    provider?: OpenAICompatProvider;
}
/** Whether `platform` may fill its model list from its own /models. */
export declare function builtinDiscoveryEligibility(db: Db, platform: string): DiscoveryEligibility;
export declare function isBuiltinDiscoveryEligible(db: Db, platform: string): boolean;
/** A human sentence for an ineligible platform, for route errors. */
export declare function ineligibleMessage(platform: string, reason: IneligibleReason | undefined): string;
interface KeyRow {
    id: number;
    platform: string;
    encrypted_key: string;
    iv: string;
    auth_tag: string;
    proxy_encrypted?: string | null;
    proxy_iv?: string | null;
    proxy_auth_tag?: string | null;
}
/** Fetch the platform's /models with one of its keys, through that key's own
 *  proxy (#590), exactly as the health check reaches it. */
export declare function discoverBuiltinModels(provider: OpenAICompatProvider, key: KeyRow, apiKeyOverride?: string): Promise<DiscoveredModel[]>;
/** Discovered model ids already present on this platform, in any provenance. */
export declare function registeredModelIds(db: Db, platform: string): Set<string>;
export interface DiscoveredEntry {
    modelId: string;
    contextWindow?: number;
    vision?: boolean;
}
export interface RegisterDiscoveredResult {
    created: string[];
    /** Already present (catalog, user or earlier discovery): left untouched. */
    existing: string[];
    /** Deleted by the operator and not lifted (automatic passes only). */
    tombstoned: string[];
}
/**
 * Insert discovered chat models for a built-in platform. INSERT-only: a row
 * that already exists for (platform, model_id) in the built-in scope is never
 * updated, so catalog rows, user rows and anything the operator tuned by hand
 * all win. `explicit` marks a pick the operator made in the dashboard, which
 * lifts a previous deletion, the way re-adding a custom model does (#926).
 */
export declare function registerDiscoveredModels(db: Db, platform: string, entries: DiscoveredEntry[], options: {
    explicit: boolean;
}): RegisterDiscoveredResult;
/**
 * Which discovered models an AUTOMATIC pass may register. Stricter than a
 * dashboard pick, because nobody looked at the list:
 *  - chat only: embedding, image, audio, transcription and video ids are
 *    skipped (#1051), as in the custom-model sync;
 *  - an upstream that prices a model and says it is not free is skipped;
 *  - CUSTOM_MODEL_SYNC_FREE_PATTERNS, when set, applies here too (#746).
 */
export declare function autoRegistrable(models: DiscoveredModel[]): {
    accepted: DiscoveredModel[];
    nonChat: number;
    paid: number;
};
export interface BuiltinDiscoveryResult {
    platforms: number;
    added: number;
    skipped: number;
    tombstoned: number;
    nonChatSkipped: number;
    paidSkipped: number;
    failures: Array<{
        platform: string;
        error: string;
    }>;
}
/**
 * One automatic discovery pass over every eligible platform that has a usable
 * key (or just `only`, when given). ADD-ONLY, like the custom-model sync: a
 * model that vanishes upstream is left for the health and retirement paths.
 */
export declare function runBuiltinModelDiscovery(db: Db, only?: string): Promise<BuiltinDiscoveryResult>;
export declare function triggerBuiltinModelDiscovery(db: Db, platform: string, reason: 'key_added' | 'healthy'): Promise<BuiltinDiscoveryResult> | null;
/** Test hook: forget event throttling between cases. */
export declare function resetBuiltinDiscoveryThrottle(): void;
/** Run the pass on the custom-model sync cadence (CUSTOM_MODEL_SYNC_INTERVAL_MS,
 *  daily by default; 0 disables both). */
export declare function startBuiltinModelDiscovery(db: Db, scheduler: Scheduler): (() => void) | null;
export {};
//# sourceMappingURL=builtin-model-discovery.d.ts.map