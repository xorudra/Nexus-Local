function hasColumn(db, table, column) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    return columns.some((candidate) => candidate.name === column);
}
/** Persist the most recent failed health-probe reason for local diagnostics. */
export function up(db) {
    if (!hasColumn(db, 'api_keys', 'last_health_error')) {
        db.prepare('ALTER TABLE api_keys ADD COLUMN last_health_error TEXT').run();
    }
}
export function down(db) {
    if (hasColumn(db, 'api_keys', 'last_health_error')) {
        db.prepare('ALTER TABLE api_keys DROP COLUMN last_health_error').run();
    }
}
//# sourceMappingURL=20260720_000001_key_health_error.js.map