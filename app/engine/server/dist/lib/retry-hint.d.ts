/** One chain walk's view of the upstream back-offs. */
export declare class RetryHintTracker {
    private minMs;
    private unknown;
    private attempts;
    /** Record one failed candidate. `retryAfterMs` is the stated back-off, if any. */
    record(status: number, retryAfterMs: number | undefined): void;
    /** The soonest stated back-off when every recorded failure was a 429 carrying
     *  one; undefined otherwise (including when nothing was recorded). */
    retryAfterMs(): number | undefined;
}
/** Milliseconds → whole Retry-After seconds (ceil, at least 1). */
export declare function retryAfterSeconds(ms: number): number;
//# sourceMappingURL=retry-hint.d.ts.map