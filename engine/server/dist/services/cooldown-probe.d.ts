import type { Scheduler } from '../lib/scheduler.js';
import { type KeyProbeOutcome } from './health.js';
export interface ProbePassOptions {
    now?: number;
    probe?: (keyId: number) => Promise<KeyProbeOutcome>;
    jitter?: () => number;
    maxProbes?: number;
}
export interface ProbePassResult {
    probedKeyIds: number[];
    clearedCooldowns: number;
}
/**
 * One probe pass: find ripe heuristic cooldowns, probe up to maxProbes of their
 * keys (respecting per-key backoff), and clear every heuristic cooldown on a
 * key whose probe passed. Exported for tests; production runs it on the
 * scheduler via startCooldownProbe.
 */
export declare function runCooldownProbePass(opts?: ProbePassOptions): Promise<ProbePassResult>;
export declare function startCooldownProbe(scheduler: Scheduler): void;
export declare function stopCooldownProbe(): void;
/** Test seam: drop all per-key probe pacing state. */
export declare function resetCooldownProbeState(): void;
//# sourceMappingURL=cooldown-probe.d.ts.map