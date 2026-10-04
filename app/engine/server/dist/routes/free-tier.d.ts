/**
 * Free-tier budget dashboard (#905).
 *
 * Pool-deduped monthly budget overview: the models table carries per-model
 * labels like '~120M' / '~3M (1k credits)' / 'credits-based'; many models on
 * one platform share the same free pool (see inferQuotaPoolKey), so summing
 * every model's label would double-count. We take ONE documented budget per
 * pool (the largest parseBudget value seen in it) and report the pools
 * alongside live quota observations (used/remaining/reset) when the provider
 * reports them.
 *
 * The model set, the key-count scaling and the enabled semantics deliberately
 * match GET /api/fallback/token-usage (the stacked bar whose legend these pools
 * group), so the two never disagree about the same pool:
 *   - only platforms that actually have an enabled key are counted;
 *   - a documented budget is per account, so it is scaled by the usable
 *     (enabled + healthy/unknown) key count for the platform;
 *   - chain-disabled rows still contribute to the pool (they share the same
 *     provider allowance) and are only marked, never dropped.
 */
export declare const freeTierRouter: import("express-serve-static-core").Router;
//# sourceMappingURL=free-tier.d.ts.map