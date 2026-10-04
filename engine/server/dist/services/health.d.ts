import type { KeyStatus } from '@freellmapi/shared/types.js';
import type { Scheduler } from '../lib/scheduler.js';
/** Base cadence of the scheduled pass (jittered per run, see
 *  nextHealthCheckDelayMs). Exported for tests. */
export declare const HEALTH_CHECK_INTERVAL_MS: number;
export declare const RECENT_CHECK_SKIP_MS: number;
export declare const HEALTH_PASS_TIME_BUDGET_MS: number;
export declare function checkKeyHealth(keyId: number): Promise<KeyStatus>;
export type KeyProbeOutcome = 'valid' | 'invalid' | 'error';
export declare function probeKeyValidity(keyId: number): Promise<KeyProbeOutcome>;
/**
 * Promote a key out of 'error' after it successfully served a live request.
 *
 * Serving traffic is stronger evidence than any probe, so a key stuck at 'error'
 * from an earlier transport blip should not have to wait for the next health pass
 * to become routable again. Deliberately narrow: 'invalid' means a provider
 * confirmed the credential is bad, and only a real validateKey pass clears that.
 */
export declare function markKeyHealthyFromRequest(keyId: number): void;
export interface HealthPassOptions {
    /** Probe every enabled key now: no recency skip, no per-provider spacing.
     *  Used by the dashboard's "check all" button and the post-wake re-probe,
     *  where the point is an immediate, complete picture. */
    force?: boolean;
    /** Test seams: injectable clock, sleep, probe and pool size, mirroring the
     *  cooldown-probe pass so a pacing test needs no real timers. */
    now?: () => number;
    sleep?: (ms: number) => Promise<void>;
    check?: (keyId: number) => Promise<unknown>;
    concurrency?: number;
    minSpacingMs?: number;
}
export interface HealthPassResult {
    /** Keys probed this pass, in the order the pass started them. */
    checkedKeyIds: number[];
    /** Enabled keys left alone because they were validated recently. */
    skippedKeyIds: number[];
}
/**
 * Round-robin the queue across providers: one key from each provider, then the
 * next from each, and so on. Raw DB order is provider-clustered (keys are added
 * a provider at a time), which is what turned a fleet with 40 keys on one
 * provider into 40 back-to-back requests from one IP (#553). Exported for tests.
 */
export declare function interleaveByProvider<T>(rows: T[], bucketOf: (row: T) => string): T[];
export declare function checkAllKeys(opts?: HealthPassOptions): Promise<HealthPassResult>;
/** Delay until the next scheduled pass: the base interval ±20%, so restarts and
 *  co-deployed gateways don't stay phase-locked on the same providers. */
export declare function nextHealthCheckDelayMs(jitter?: () => number): number;
export declare function startHealthChecker(scheduler: Scheduler): void;
export declare function stopHealthChecker(): void;
//# sourceMappingURL=health.d.ts.map