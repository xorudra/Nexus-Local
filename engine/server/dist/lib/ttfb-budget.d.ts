export interface EndpointTtfbStats {
    p50Ms: number;
    p95Ms: number;
    sampleCount: number;
    weightedSamples: number;
}
/** Clear the derived cache; the request log remains the source of truth. */
export declare function invalidateTtfbBudgetCache(): void;
/** Decay-weighted nearest-rank percentiles of successful endpoint TTFB. */
export declare function getEndpointTtfbStats(platform: string, endpointScope?: string, now?: number): EndpointTtfbStats | null;
/** Give historically slow endpoints their P95 TTFB plus a safety buffer. */
export declare function getEndpointTimeBudgetMs(baseBudgetMs: number, platform: string, endpointScope?: string, now?: number): number;
//# sourceMappingURL=ttfb-budget.d.ts.map