/** How many DISTINCT requests must report a 'probable' signal before acting. */
export declare const RETIREMENT_CONFIRMATIONS_REQUIRED = 2;
/**
 * Corroboration has to be recent. Two "no longer available" 404s a week apart
 * are two outages; two within the hour are a retirement.
 */
export declare const RETIREMENT_OBSERVATION_WINDOW_MS: number;
/** Test seam: the counters are process-local and deliberately not persisted. */
export declare function resetModelRetirementObservations(): void;
export interface RetirementRoute {
    modelDbId: number;
    platform: string;
    modelId: string;
    /**
     * The endpoint this route belongs to, for custom relays (#651). Two relays
     * can serve the same model id; a 410 from one says nothing about the other,
     * so their corroboration counters must not share a bucket. Absent/'' for
     * catalog platforms, which keeps their key exactly what it always was.
     */
    endpointScope?: string;
}
/**
 * Record one upstream failure against the retirement heuristic and, when the
 * evidence is strong enough, auto-disable the model. Returns true iff this call
 * retired it. Never throws: it runs on the proxy's failure path, where a DB
 * hiccup must not turn a failover into a crash.
 */
export declare function noteModelRetirementSignal(route: RetirementRoute, err: unknown, requestToken?: unknown): boolean;
//# sourceMappingURL=model-retirement.d.ts.map