import type { Db } from '../db/types.js';
export interface CustomModelSeed {
    sizeLabel: string;
    intelligenceRank: number;
    speedRank: number;
}
/** Used when there is no catalog to measure (fresh install, catalog cleared).
 *  Mid-tier and mid-rank, matching the historical numeric defaults but with a
 *  size_label the router can actually score. */
export declare const FALLBACK_CUSTOM_SEED: CustomModelSeed;
/**
 * The intelligence/speed/tier a newly registered custom model should start at:
 * the median of the operator's catalog models. Custom rows are excluded so the
 * seed can't drift toward previously seeded custom models, and size labels the
 * router doesn't recognize are ignored when picking the median tier.
 */
export declare function customModelSeed(db: Db): CustomModelSeed;
//# sourceMappingURL=custom-model-seed.d.ts.map