import { tierValue, TIER_VALUE } from './scoring.js';
/** Used when there is no catalog to measure (fresh install, catalog cleared).
 *  Mid-tier and mid-rank, matching the historical numeric defaults but with a
 *  size_label the router can actually score. */
export const FALLBACK_CUSTOM_SEED = {
    sizeLabel: 'Medium',
    intelligenceRank: 50,
    speedRank: 50,
};
/** Lower median: on an even-sized sample take the smaller of the two middles so
 *  the seed never over-claims a tier the catalog only half supports. */
function lowerMedian(values, rank) {
    if (values.length === 0)
        return undefined;
    const sorted = [...values].sort((a, b) => rank(a) - rank(b));
    return sorted[Math.floor((sorted.length - 1) / 2)];
}
/**
 * The intelligence/speed/tier a newly registered custom model should start at:
 * the median of the operator's catalog models. Custom rows are excluded so the
 * seed can't drift toward previously seeded custom models, and size labels the
 * router doesn't recognize are ignored when picking the median tier.
 */
export function customModelSeed(db) {
    const rows = db.prepare(`
    SELECT size_label, intelligence_rank, speed_rank
      FROM models
     WHERE platform != 'custom'
  `).all();
    if (rows.length === 0)
        return FALLBACK_CUSTOM_SEED;
    const tiered = rows.filter(r => r.size_label in TIER_VALUE);
    const medianTier = lowerMedian(tiered, r => tierValue(r.size_label));
    const medianIntelligence = lowerMedian(rows, r => r.intelligence_rank);
    const medianSpeed = lowerMedian(rows, r => r.speed_rank);
    return {
        sizeLabel: medianTier?.size_label ?? FALLBACK_CUSTOM_SEED.sizeLabel,
        intelligenceRank: medianIntelligence?.intelligence_rank ?? FALLBACK_CUSTOM_SEED.intelligenceRank,
        speedRank: medianSpeed?.speed_rank ?? FALLBACK_CUSTOM_SEED.speedRank,
    };
}
//# sourceMappingURL=custom-model-seed.js.map