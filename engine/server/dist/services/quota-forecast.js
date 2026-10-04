import { getQuotaStateForKeys, inferPoolForPlatform } from './provider-quota.js';
import { getDb } from '../db/index.js';
// Daily free-tier balance forecast (#1104). Free tiers reset on a per-account
// window (usually UTC midnight) and the only way to know how much headroom is
// left before that reset is to read what the providers themselves reported.
// This is a pure aggregation over `getQuotaStateForKeys()` — no new tables, no
// extra probes — so it costs nothing beyond the query the health view already
// runs.
//
// The value it adds over the raw rows: one number per platform that answers
// "can I keep calling this platform for the rest of today?", plus a
// low-balance warning an agent can gate on BEFORE sending a request that would
// 429.
export const LOW_BALANCE_THRESHOLD = 0.1; // <10% of the daily window left → warn
export const LOW_BALANCE_ABSOLUTE = 20; // ...or fewer than 20 requests left
// The absolute floor is a statement about big windows: "20 left" is alarming
// out of 14400/day and unremarkable out of 30/day. Below this limit the
// percentage rule alone decides, otherwise a small tier would warn from its
// first request onwards and the flag would mean nothing.
export const LOW_BALANCE_ABSOLUTE_MIN_LIMIT = 200;
// Rate observation window: look at requests in the last N minutes to estimate
// current consumption speed. Ten minutes covers bursty usage while ignoring
// sub-hour lulls; shorter windows would jitter, longer ones would lag.
export const RATE_OBSERVATION_WINDOW_MINUTES = 10;
export const MIN_FORECAST_REQUESTS = 3;
function secondsUntilReset(resetAt) {
    if (!resetAt)
        return null;
    const ms = new Date(resetAt).getTime() - Date.now();
    if (Number.isNaN(ms) || ms <= 0)
        return null;
    return Math.floor(ms / 1000);
}
export function getRecentQuotaActivity(now) {
    const sqliteUtc = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
    const since = sqliteUtc(now - RATE_OBSERVATION_WINDOW_MINUTES * 60_000);
    const rows = getDb().prepare(`
    SELECT platform, key_id AS keyId, model_id AS modelId, COUNT(*) AS count
      FROM requests
     WHERE created_at >= ? AND datetime(created_at) >= ? AND datetime(created_at) <= ?
       AND status = 'success'
     GROUP BY platform, key_id, model_id
  `).all(since, since, sqliteUtc(now));
    return rows.map(row => ({ platform: row.platform, keyId: row.keyId,
        pool: inferPoolForPlatform(row.platform, row.modelId), count: Number(row.count) }));
}
export function estimateExhaustionAt(remaining, ratePerMin, resetAt, now) {
    // No observed rate → no honest projection. Rates too low to matter are
    // excluded at the caller level (rate_per_min itself is null).
    if (ratePerMin === null || ratePerMin <= 0)
        return null;
    // Remaining is known (caller checks) and limit is positive (enforced below).
    const minutesUntilEmpty = remaining / ratePerMin;
    const secondsFromNow = Math.ceil(minutesUntilEmpty * 60);
    const ms = now + secondsFromNow * 1000;
    // Never project past the natural window reset: if the window expires first,
    // we have headroom even if the request count would otherwise exhaust the
    // pool — the quota header tracks the remaining *before* reset, not absolute
    // spending.
    const resetMs = resetAt ? new Date(resetAt).getTime() : Infinity;
    if (!Number.isFinite(ms) || Number.isNaN(resetMs) || ms >= resetMs || ms <= now)
        return null;
    return new Date(ms).toISOString();
}
function entryFor(row, ratePerMin, now) {
    // Only request-based windows are predictable from quota headers; token pools
    // reset semantics vary too much across providers to forecast honestly.
    if (row.metric !== 'requests')
        return null;
    // Without a known limit there is no window to forecast — nothing to warn on.
    if (typeof row.limit !== 'number' || row.limit <= 0)
        return null;
    const limit = row.limit;
    const remaining = typeof row.remaining === 'number' ? row.remaining : null;
    // An unknown `remaining` says nothing about consumption: reporting the whole
    // limit as used would read as an exhausted pool when it may be untouched.
    const used = remaining === null ? null : Math.max(0, limit - remaining);
    let remainingPct = null;
    let lowBalance = false;
    if (remaining !== null) {
        remainingPct = Math.max(0, Math.min(100, Math.round((remaining / limit) * 100)));
        const absoluteApplies = limit >= LOW_BALANCE_ABSOLUTE_MIN_LIMIT;
        lowBalance = (absoluteApplies && remaining <= LOW_BALANCE_ABSOLUTE)
            || remaining / limit < LOW_BALANCE_THRESHOLD;
    }
    // Rate projection is gated on remaining being known (unknown remaining makes
    // any rate look like a free lunch until the next quota refresh).
    if (remaining === null)
        ratePerMin = null;
    const estimatedExhaustionAt = (remaining !== null && ratePerMin !== null && remaining > 0)
        ? estimateExhaustionAt(remaining, ratePerMin, row.resetAt ?? null, now)
        : null;
    return {
        platform: row.platform,
        pool: row.quotaPoolKey ?? `${row.platform}::default`,
        used,
        remaining,
        limit,
        remaining_pct: remainingPct,
        reset_at: row.resetAt ?? null,
        low_balance: lowBalance,
        seconds_until_reset: secondsUntilReset(row.resetAt ?? null),
        rate_per_min: ratePerMin,
        estimated_exhaustion_at: estimatedExhaustionAt,
    };
}
// Dedupe to the TIGHTEST row per platform+pool: a platform with several keys
// sharing one account pool reports the same window per key, and the number that
// matters for "can I keep calling" is the least headroom left.
export function getQuotaForecast(rows = getQuotaStateForKeys(), now = Date.now()) {
    const byKey = new Map();
    const activity = rows.length ? getRecentQuotaActivity(now) : [];
    const counts = new Map();
    for (const row of activity) {
        const identity = JSON.stringify([row.platform, row.pool, row.keyId]);
        counts.set(identity, (counts.get(identity) ?? 0) + row.count);
    }
    const poolKeys = new Map();
    for (const row of rows) {
        if (row.metric !== 'requests')
            continue;
        const pool = JSON.stringify([row.platform, row.quotaPoolKey]);
        const keys = poolKeys.get(pool) ?? new Set();
        keys.add(JSON.stringify([row.platform, row.quotaPoolKey, row.keyId]));
        poolKeys.set(pool, keys);
    }
    for (const row of rows) {
        const keys = poolKeys.get(JSON.stringify([row.platform, row.quotaPoolKey])) ?? [];
        let count = 0;
        for (const key of keys)
            count += counts.get(key) ?? 0;
        const rate = count < MIN_FORECAST_REQUESTS ? null : Math.round(count / RATE_OBSERVATION_WINDOW_MINUTES * 100) / 100;
        const entry = entryFor(row, rate, now);
        if (!entry)
            continue;
        // `pool` already carries its platform ("groq::account"), so it is the key.
        const key = entry.pool;
        const prev = byKey.get(key);
        if (!prev || (entry.remaining_pct ?? Infinity) < (prev.remaining_pct ?? Infinity)) {
            byKey.set(key, entry);
        }
    }
    return [...byKey.values()].sort((a, b) => {
        // Low-balance pools first — the ones the caller most needs to see.
        if (a.low_balance !== b.low_balance)
            return a.low_balance ? -1 : 1;
        return a.platform.localeCompare(b.platform);
    });
}
//# sourceMappingURL=quota-forecast.js.map