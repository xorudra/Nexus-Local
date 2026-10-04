// Migration: record WHY a catalog model was tombstoned
// Created: 2026-07-28
//
// DOWN: reversible — drops the two added columns (every existing tombstone is
// a user deletion, which is the default the columns backfill to).
function hasColumn(db, table, column) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    return columns.some((candidate) => candidate.name === column);
}
/**
 * Tombstones used to mean exactly one thing: "the user deleted this catalog
 * model, keep it deleted across syncs". Issue #634 adds a second, machine-made
 * kind — "the provider retired this model upstream (410 / end of life)" — which
 * disables the row instead of deleting it and carries the upstream wording so
 * the dashboard can say why. `source` keeps the two apart ('user' is the
 * backfill for every pre-existing row); `reason` is the redacted provider text.
 */
export function up(db) {
    if (!hasColumn(db, 'catalog_model_tombstones', 'source')) {
        db.prepare("ALTER TABLE catalog_model_tombstones ADD COLUMN source TEXT NOT NULL DEFAULT 'user'").run();
    }
    if (!hasColumn(db, 'catalog_model_tombstones', 'reason')) {
        db.prepare('ALTER TABLE catalog_model_tombstones ADD COLUMN reason TEXT').run();
    }
}
export function down(db) {
    // Upstream-retirement tombstones have no meaning without their source column,
    // and leaving them behind would silently delete live models on the next sync.
    db.prepare("DELETE FROM catalog_model_tombstones WHERE source = 'upstream_eol'").run();
    if (hasColumn(db, 'catalog_model_tombstones', 'reason')) {
        db.prepare('ALTER TABLE catalog_model_tombstones DROP COLUMN reason').run();
    }
    if (hasColumn(db, 'catalog_model_tombstones', 'source')) {
        db.prepare('ALTER TABLE catalog_model_tombstones DROP COLUMN source').run();
    }
}
//# sourceMappingURL=20260728_000001_tombstone_provenance.js.map