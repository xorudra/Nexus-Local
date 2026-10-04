import { getDb } from '../db/index.js';
// Healthy keys are the ones the router can actually use. 'unknown' counts as
// healthy: an unprobed key is treated as usable until a probe says otherwise
// (the router does the same for skip/fallback decisions).
const HEALTHY_STATUSES = new Set(['healthy', 'unknown']);
function positiveEnv(raw, fallback) {
    if (raw !== undefined && raw.trim() !== '') {
        const n = Number(raw);
        if (Number.isFinite(n) && n > 0)
            return n;
    }
    return fallback;
}
// Fraction of providers that must remain healthy to stay out of degraded mode.
const DEGRADED_HEALTHY_RATIO = positiveEnv(process.env.DEGRADED_HEALTHY_RATIO, 0.5);
// Only meaningful when there are at least this many enabled providers — a
// single-provider deployment shouldn't flap degraded mode every outage.
const DEGRADED_MIN_PROVIDERS = positiveEnv(process.env.DEGRADED_MIN_PROVIDERS, 3);
// How long the ratio must stay below the threshold before entering degraded
// mode, so a transient bad pass doesn't flip the gateway.
const DEGRADED_ENTRY_GRACE_MS = positiveEnv(process.env.DEGRADED_ENTRY_GRACE_MS, 60_000);
// How long the ratio must stay at/above the threshold before exiting degraded
// mode. Longer than the entry grace: exiting prematurely re-enters quickly.
const DEGRADED_EXIT_GRACE_MS = positiveEnv(process.env.DEGRADED_EXIT_GRACE_MS, 120_000);
const state = {
    state: 'normal',
    degradedAt: null,
    belowSince: null,
    recoveredSince: null,
};
let lastSnapshot = null;
/** Compute the current healthy-provider ratio from the key table. Exported for
 *  tests to inject a fake DB; callers normally use updateDegradationState. */
export function computeHealthSnapshot() {
    const db = getDb();
    const rows = db.prepare(`
    SELECT platform, status
    FROM api_keys
    WHERE enabled = 1
  `).all();
    const usable = new Set();
    const present = new Set();
    for (const row of rows) {
        present.add(row.platform);
        if (HEALTHY_STATUSES.has(row.status))
            usable.add(row.platform);
    }
    const totalProviders = present.size;
    const healthyProviders = usable.size;
    const ratio = totalProviders === 0 ? 1 : healthyProviders / totalProviders;
    const snapshot = { healthyProviders, totalProviders, ratio };
    lastSnapshot = snapshot;
    return snapshot;
}
/** Re-evaluate the degraded state from the current key table. Call this after
 *  every health pass; also callable on demand (dashboard, router entry). */
export function updateDegradationState(now = Date.now()) {
    const snapshot = computeHealthSnapshot();
    // Degradation is only meaningful with enough providers to judge.
    if (snapshot.totalProviders < DEGRADED_MIN_PROVIDERS) {
        state.state = 'normal';
        state.degradedAt = null;
        state.belowSince = null;
        state.recoveredSince = null;
        return getDegradationStatus();
    }
    const belowThreshold = snapshot.ratio < DEGRADED_HEALTHY_RATIO;
    if (belowThreshold) {
        state.recoveredSince = null;
        if (state.state === 'normal') {
            state.belowSince ??= now;
            if (now - state.belowSince >= DEGRADED_ENTRY_GRACE_MS) {
                state.state = 'degraded';
                state.degradedAt = now;
                console.warn(`[Degradation] Entering degraded mode: ${snapshot.healthyProviders}/${snapshot.totalProviders} providers healthy ` +
                    `(${(snapshot.ratio * 100).toFixed(0)}% < ${(DEGRADED_HEALTHY_RATIO * 100).toFixed(0)}%)`);
            }
        }
    }
    else {
        state.belowSince = null;
        if (state.state === 'degraded') {
            state.recoveredSince ??= now;
            if (now - state.recoveredSince >= DEGRADED_EXIT_GRACE_MS) {
                state.state = 'normal';
                state.degradedAt = null;
                console.log(`[Degradation] Exiting degraded mode: ${snapshot.healthyProviders}/${snapshot.totalProviders} providers healthy ` +
                    `(${(snapshot.ratio * 100).toFixed(0)}% >= ${(DEGRADED_HEALTHY_RATIO * 100).toFixed(0)}%)`);
            }
        }
        else {
            state.recoveredSince = null;
        }
    }
    return getDegradationStatus();
}
export function isDegraded() {
    return state.state === 'degraded';
}
export function getDegradationStatus() {
    const snapshot = lastSnapshot ?? computeHealthSnapshot();
    return {
        ...snapshot,
        state: state.state,
        degradedAt: state.degradedAt,
    };
}
/** Reset the machine (tests, and the post-start re-probe path). */
export function resetDegradationState() {
    state.state = 'normal';
    state.degradedAt = null;
    state.belowSince = null;
    state.recoveredSince = null;
    lastSnapshot = null;
}
//# sourceMappingURL=degradation.js.map