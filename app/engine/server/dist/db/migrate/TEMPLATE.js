// Migration: <short description>
// Created: <YYYY-MM-DD>
//
// DOWN: <reversible | irreversible - reason>
export function up(db) {
    db.exec(`
    -- your SQL here
  `);
}
export function down(db) {
    // If reversible:
    db.exec(`
    -- inverse SQL here
  `);
    // If irreversible:
    // throw new Error('irreversible migration: <reason>');
}
//# sourceMappingURL=TEMPLATE.js.map