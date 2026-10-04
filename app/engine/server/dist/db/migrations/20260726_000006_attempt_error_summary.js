// Migration: request_attempts.error_summary — per-hop error text for the ladder
// Created: 2026-07-26
//
// DOWN: reversible
//
// The failover-ladder drill-down (issue #335) renders WHY each hop failed, but
// the `outcome` class alone loses the provider's actual words ("rate limit
// reached for llama-3.3-70b, retry in 7m12s" collapses to 'rate_limited').
// This nullable column stores a short, REDACTED summary of the per-attempt
// error — sanitized through lib/error-redaction.ts (same rules as the error
// text on the parent `requests` row: keys/tokens/URLs scrubbed) and capped at
// 200 chars at write time (lib/fallback-loop.ts). NULL for successful hops
// ('ok'/'committed') and for every pre-existing row, where the detail is
// simply unknown.
function hasColumn(db, table, column) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    return columns.some((candidate) => candidate.name === column);
}
export function up(db) {
    if (!hasColumn(db, 'request_attempts', 'error_summary')) {
        db.prepare('ALTER TABLE request_attempts ADD COLUMN error_summary TEXT').run();
    }
}
export function down(db) {
    if (hasColumn(db, 'request_attempts', 'error_summary')) {
        db.prepare('ALTER TABLE request_attempts DROP COLUMN error_summary').run();
    }
}
//# sourceMappingURL=20260726_000006_attempt_error_summary.js.map