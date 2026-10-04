/**
 * Global degraded-mode state machine (#904).
 *
 * When a large share of enabled providers fails at once, per-request probing
 * and bandit exploration just burn retry budget on dead routes. This module
 * tracks the healthy-provider ratio (driven by the scheduled health pass) and
 * flips the gateway into a degraded state once the ratio stays below a
 * threshold for a sustained period. While degraded, the router skips
 * exploration and sticks to the scored order of remaining healthy providers;
 * the health endpoint reports the state so operators can see it.
 *
 * Recovery is the mirror image: the ratio must stay at or above the threshold
 * for a sustained period before the gateway exits degraded mode, so a single
 * flickering pass doesn't flap the state.
 */
export type DegradationState = 'normal' | 'degraded';
export interface HealthSnapshot {
    /** Enabled providers that still have at least one usable key. */
    healthyProviders: number;
    /** Enabled providers with at least one key, usable or not. */
    totalProviders: number;
    /** healthyProviders / totalProviders, 1 when there are no providers. */
    ratio: number;
}
export interface DegradationStatus extends HealthSnapshot {
    state: DegradationState;
    /** ms since epoch when degraded mode was entered; null while normal. */
    degradedAt: number | null;
}
/** Compute the current healthy-provider ratio from the key table. Exported for
 *  tests to inject a fake DB; callers normally use updateDegradationState. */
export declare function computeHealthSnapshot(): HealthSnapshot;
/** Re-evaluate the degraded state from the current key table. Call this after
 *  every health pass; also callable on demand (dashboard, router entry). */
export declare function updateDegradationState(now?: number): DegradationStatus;
export declare function isDegraded(): boolean;
export declare function getDegradationStatus(): DegradationStatus;
/** Reset the machine (tests, and the post-start re-probe path). */
export declare function resetDegradationState(): void;
//# sourceMappingURL=degradation.d.ts.map