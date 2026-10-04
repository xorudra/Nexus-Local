/**
 * Per-key monthly budget (#1158): optional request/token caps per api_keys row,
 * enforced against the CURRENT UTC month's successful requests. A key at its
 * cap returns `quota_exceeded` (429) with a Retry-After of "seconds until the
 * next month" — the semantic GateLLM-style rejection so an agent knows when the
 * window resets instead of hammering a 429.
 *
 * Successful usage is retained in key_monthly_usage independently of analytics
 * retention. Active requests reserve their estimated tokens until their route
 * is released. Actual provider usage is settled by the request-log transaction;
 * token estimates are an admission guard, not an exact upstream billing cap.
 * Caps are opt-in (0 = unlimited) and reset on UTC month boundaries.
 */
import { getDb } from '../db/index.js';
function utcNextMonthStartMs(now = Date.now()) {
    const d = new Date(now);
    const month = d.getUTCMonth() + 1;
    return Date.UTC(d.getUTCFullYear() + Math.floor(month / 12), month % 12, 1);
}
// These requests belong to this process and remain reserved until completion,
// even if a stream outlives the short rate-limit lease timeout. A restarted
// process has no active requests; completed usage remains in SQLite.
const reservations = new WeakMap();
function activeReservations() {
    const db = getDb();
    let active = reservations.get(db);
    if (!active) {
        active = new Set();
        reservations.set(db, active);
    }
    return active;
}
export function getMonthlyBudgetCaps(keyId) {
    const row = getDb().prepare('SELECT monthly_request_cap, monthly_token_cap FROM api_keys WHERE id = ?').get(keyId);
    if (!row)
        return { requestCap: 0, tokenCap: 0 };
    return { requestCap: row.monthly_request_cap, tokenCap: row.monthly_token_cap };
}
export function setMonthlyBudgetCaps(keyId, patch) {
    const sets = [];
    const values = [];
    if (patch.requestCap !== undefined) {
        sets.push('monthly_request_cap = ?');
        values.push(patch.requestCap);
    }
    if (patch.tokenCap !== undefined) {
        sets.push('monthly_token_cap = ?');
        values.push(patch.tokenCap);
    }
    if (sets.length === 0)
        return false;
    const result = getDb().prepare(`UPDATE api_keys SET ${sets.join(', ')} WHERE id = ?`).run(...values, keyId);
    return result.changes > 0;
}
export function getMonthlyUsage(keyId, now = Date.now()) {
    const row = getDb().prepare(`
    SELECT requests, tokens FROM key_monthly_usage WHERE key_id = ? AND month = ?
  `).get(keyId, new Date(now).toISOString().slice(0, 7));
    return { requests: Number(row?.requests ?? 0), tokens: Number(row?.tokens ?? 0) };
}
/**
 * Check a key against its monthly caps, taking the current month's successful
 * usage plus the tokens THIS request would add. Returns allowed when both caps
 * are 0 (unlimited) or neither would be exceeded.
 */
export function checkMonthlyBudget(keyId, estimatedTokens, now = Date.now()) {
    const caps = getMonthlyBudgetCaps(keyId);
    if (caps.requestCap <= 0 && caps.tokenCap <= 0)
        return { allowed: true };
    const usage = getMonthlyUsage(keyId, now);
    for (const reservation of activeReservations()) {
        if (reservation.keyId !== keyId)
            continue;
        usage.requests++;
        usage.tokens += reservation.tokens;
    }
    if (caps.requestCap > 0 && usage.requests >= caps.requestCap) {
        return { allowed: false, reason: 'monthly_request_cap', retryAfterSec: secondsUntilNextMonth(now) };
    }
    if (caps.tokenCap > 0 && (usage.tokens >= caps.tokenCap || usage.tokens + Math.max(0, estimatedTokens) > caps.tokenCap)) {
        return { allowed: false, reason: 'monthly_token_cap', retryAfterSec: secondsUntilNextMonth(now) };
    }
    return { allowed: true };
}
/** Check and reserve synchronously before dispatch; release on every terminal path. */
export function reserveMonthlyBudget(keyId, estimatedTokens) {
    const verdict = checkMonthlyBudget(keyId, estimatedTokens);
    if (!verdict.allowed)
        return verdict;
    const active = activeReservations();
    const reservation = { keyId, tokens: Math.max(0, estimatedTokens) };
    active.add(reservation);
    return { allowed: true, release: () => { active.delete(reservation); } };
}
/** Seconds from `now` until the next UTC month boundary — the Retry-After value. */
export function secondsUntilNextMonth(now = Date.now()) {
    return Math.max(1, Math.floor((utcNextMonthStartMs(now) - now) / 1000));
}
/** ISO timestamp of the next UTC month boundary (for headers / diagnostics). */
export function nextMonthResetAt(now = Date.now()) {
    return new Date(utcNextMonthStartMs(now)).toISOString();
}
//# sourceMappingURL=key-budget.js.map