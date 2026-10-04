import type { Db } from './types.js';
/**
 * Paid-equivalent pricing per model: what the SAME model (or its nearest
 * equivalent) costs per million tokens on paid APIs. Used by the analytics
 * "Est. savings" stat so it reflects realistic savings rather than pricing
 * every token like a frontier model.
 *
 * Source: OpenRouter public pricing API (paid, non-:free variants),
 * snapshot 2026-06-05; closed models use their official API prices.
 * `null` = no paid equivalent exists (stealth/preview models) — analytics
 * falls back to a modest default.
 *
 * Format: [platform, model_id, $/M input, $/M output]
 */
type PricingRow = [string, string, number | null, number | null];
export declare const MODEL_PRICING: PricingRow[];
/** Fallback $/M for models with no mapping (custom endpoints, stealth). */
export declare const FALLBACK_INPUT_PER_M = 0.2;
export declare const FALLBACK_OUTPUT_PER_M = 0.8;
/**
 * Adds the pricing columns (idempotent) and refreshes prices for every
 * known model. Runs on every boot — it's ~100 UPDATEs in one transaction
 * and keeps prices current when this map is updated in a release.
 */
export declare function applyModelPricing(db: Db): void;
export {};
//# sourceMappingURL=model-pricing.d.ts.map