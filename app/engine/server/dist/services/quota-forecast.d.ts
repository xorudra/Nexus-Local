import type { QuotaObservationView } from './provider-quota.js';
import type { Platform } from '@freellmapi/shared/types.js';
export declare const LOW_BALANCE_THRESHOLD = 0.1;
export declare const LOW_BALANCE_ABSOLUTE = 20;
export declare const LOW_BALANCE_ABSOLUTE_MIN_LIMIT = 200;
export declare const RATE_OBSERVATION_WINDOW_MINUTES = 10;
export declare const MIN_FORECAST_REQUESTS = 3;
export interface QuotaForecastEntry {
    /** Platform the pool belongs to, e.g. 'groq'. */
    platform: string;
    /** Human-readable pool label (platform::scope), e.g. 'groq::account'. */
    pool: string;
    /** Requests used in the current window. Null when `remaining` is unknown,
     *  since used is only ever derived from it. */
    used: number | null;
    /** Requests remaining in the current window. Null when unknown. */
    remaining: number | null;
    /** Window total. Null when the provider never reported a limit. */
    limit: number | null;
    /** 0..100 share of the window still available (best-effort). */
    remaining_pct: number | null;
    /** ISO timestamp of the window reset, or null when never observed. */
    reset_at: string | null;
    /** True when less than LOW_BALANCE_THRESHOLD of the window remains, or —
     *  on a window of at least LOW_BALANCE_ABSOLUTE_MIN_LIMIT — fewer than
     *  LOW_BALANCE_ABSOLUTE requests do. Always false when remaining is unknown. */
    low_balance: boolean;
    /** Seconds until reset_at, or null when reset_at is unknown/expired. */
    seconds_until_reset: number | null;
    /** Observed request rate in the last `RATE_OBSERVATION_WINDOW_MINUTES` minutes,
     *  or null when there is not enough recent request volume to estimate honestly.
     *  Non-null values are rounded to 2 decimal places. */
    rate_per_min: number | null;
    /** ISO timestamp of when the current window is expected to be exhausted at the
     *  observed rate, or null when the rate is too low / unknown to predict. A pool
     *  whose window has already expired or whose remaining is unknown is excluded
     *  regardless. */
    estimated_exhaustion_at: string | null;
}
/** Successful traffic grouped by the same key/pool identity used for observations. */
export interface RecentQuotaActivity {
    platform: Platform;
    keyId: number | null;
    pool: string;
    count: number;
}
export declare function getRecentQuotaActivity(now: number): RecentQuotaActivity[];
export declare function estimateExhaustionAt(remaining: number, ratePerMin: number | null, resetAt: string | null, now: number): string | null;
export declare function getQuotaForecast(rows?: QuotaObservationView[], now?: number): QuotaForecastEntry[];
//# sourceMappingURL=quota-forecast.d.ts.map