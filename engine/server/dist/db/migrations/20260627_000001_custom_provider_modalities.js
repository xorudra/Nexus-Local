function hasColumn(db, table, column) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    return columns.some(col => col.name === column);
}
function addKeyIdColumn(db, table) {
    if (!hasColumn(db, table, 'key_id')) {
        db.prepare(`ALTER TABLE ${table} ADD COLUMN key_id INTEGER`).run();
    }
}
function dropKeyIdColumn(db, table) {
    if (hasColumn(db, table, 'key_id')) {
        db.prepare(`ALTER TABLE ${table} DROP COLUMN key_id`).run();
    }
}
export function up(db) {
    addKeyIdColumn(db, 'embedding_models');
    addKeyIdColumn(db, 'media_models');
    db.prepare('CREATE INDEX IF NOT EXISTS idx_embedding_models_key_id ON embedding_models(key_id)').run();
    db.prepare('CREATE INDEX IF NOT EXISTS idx_media_models_key_id ON media_models(key_id)').run();
}
export function down(db) {
    db.prepare('DROP INDEX IF EXISTS idx_embedding_models_key_id').run();
    db.prepare('DROP INDEX IF EXISTS idx_media_models_key_id').run();
    dropKeyIdColumn(db, 'media_models');
    dropKeyIdColumn(db, 'embedding_models');
}
//# sourceMappingURL=20260627_000001_custom_provider_modalities.js.map