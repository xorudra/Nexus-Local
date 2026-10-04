function hasColumn(db, table, column) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    return columns.some((candidate) => candidate.name === column);
}
/** Optional per-key model scope (#657): a JSON array of model_id strings the
 *  key may serve. NULL = the key serves every model of its platform. */
export function up(db) {
    if (!hasColumn(db, 'api_keys', 'model_scope_json')) {
        db.prepare('ALTER TABLE api_keys ADD COLUMN model_scope_json TEXT').run();
    }
}
export function down(db) {
    if (hasColumn(db, 'api_keys', 'model_scope_json')) {
        db.prepare('ALTER TABLE api_keys DROP COLUMN model_scope_json').run();
    }
}
//# sourceMappingURL=20260805_000001_key_model_scope.js.map