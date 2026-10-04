import type { Platform, QuotaMetric, QuotaObservationSource, QuotaResetStrategy, ProviderQuotaObservation, ProviderQuotaState } from '@freellmapi/shared/types.js';
export interface QuotaObservationContext {
    platform: Platform;
    keyId?: number;
    providerAccountId?: string | null;
    modelId?: string | null;
    quotaPoolKey?: string | null;
    endpoint?: string | null;
    origin?: 'health' | 'proxy' | 'responses' | 'manual' | 'probe';
}
export interface QuotaObservationInput {
    platform?: Platform;
    keyId?: number;
    providerAccountId?: string | null;
    modelId?: string | null;
    quotaPoolKey?: string | null;
    metric?: QuotaMetric;
    limit?: number | null;
    remaining?: number | null;
    resetAt?: string | null;
    retryAfterMs?: number | null;
    resetStrategy?: QuotaResetStrategy;
    source?: QuotaObservationSource;
    statusCode?: number | null;
    notes?: string | null;
    rawJson?: string | null;
    endpoint?: string | null;
    confidence?: number;
    observedAt?: string;
}
export interface QuotaObservationView extends ProviderQuotaState {
    providerAccountId: string | null;
    modelId: string | null;
    endpoint: string | null;
    statusCode: number | null;
    retryAfterMs: number | null;
    rawJson: string | null;
    createdAt: string;
}
export declare function runWithQuotaObservationContext<T>(context: QuotaObservationContext, fn: () => T): T;
export declare function getQuotaObservationContext(): QuotaObservationContext | undefined;
export declare function inferPoolForPlatform(platform: Platform, modelId?: string | null): string;
export declare function inferQuotaPoolKey(platform: Platform, modelId?: string | null): string;
export declare function parseQuotaObservationsFromResponse(response: Response, opts?: Pick<QuotaObservationInput, 'platform' | 'modelId' | 'quotaPoolKey' | 'keyId' | 'providerAccountId' | 'endpoint'>): QuotaObservationInput[];
export declare function recordQuotaObservation(input: QuotaObservationInput): ProviderQuotaObservation | null;
export declare function recordQuotaObservationsFromResponse(response: Response, opts?: Pick<QuotaObservationInput, 'platform' | 'modelId' | 'quotaPoolKey' | 'keyId' | 'providerAccountId' | 'endpoint'>): ProviderQuotaObservation[];
/**
 * Fraction of the observed budget still available for each key of `platform`,
 * as keyId → 0..1, where 1 is untouched and 0 exhausted. Keys with no usable
 * observation are simply absent — that is not the same as "empty", and callers
 * must treat a miss as unknown rather than as zero headroom.
 *
 * A key metered on several metrics takes the WORST of them: the binding
 * constraint is what 429s, so a key with 90% of its requests but 2% of its
 * tokens left has 2% of headroom, not 90%.
 */
export declare function getKeyQuotaHeadroom(platform: Platform): Map<number, number>;
/** Drop the memoised headroom for one platform (or all of them). Called on
 *  every write so a fresh observation is visible to the very next route. */
export declare function invalidateKeyQuotaHeadroom(platform?: Platform): void;
export declare function getQuotaStateForKeys(options?: {
    normalizeExpired?: boolean;
}): QuotaObservationView[];
//# sourceMappingURL=provider-quota.d.ts.map