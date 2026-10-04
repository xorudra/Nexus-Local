// Migration: seed the /mcp lifecycle default (#925, MVP-1)
// Created: 2026-09-03
//
// DOWN: reversible
//
// The MCP introspection server used to be unconditionally on. #925 makes it a
// setting, and asks for off-by-default — but flipping it off for everyone would
// silently break every Claude Code / Cline session already pointed at /mcp, and
// the failure would look like a broken gateway rather than a new switch.
//
// So the default is decided once, here, from what the database already looks
// like when this migration runs:
//
//   - provider keys present  -> an install that has been in use, and may well
//                               have an MCP client attached: seed '1' (on), so
//                               the upgrade changes nothing until the operator
//                               turns it off.
//   - no provider keys       -> a fresh install running the whole migration
//                               stack against an empty database: seed '0'
//                               (off), which is the #925 default.
//
// An operator's own value always wins: if the row already exists (they set it
// through /api/settings/enable-mcp before upgrading, say) it is left alone.
const SETTING_KEY = 'enable_mcp';
export function up(db) {
    const existing = db.prepare('SELECT value FROM settings WHERE key = ?').get(SETTING_KEY);
    if (existing)
        return;
    const row = db.prepare('SELECT COUNT(*) AS count FROM api_keys').get();
    const isExistingInstall = row.count > 0;
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)')
        .run(SETTING_KEY, isExistingInstall ? '1' : '0');
}
export function down(db) {
    db.prepare('DELETE FROM settings WHERE key = ?').run(SETTING_KEY);
}
//# sourceMappingURL=20260903_000001_mcp_enabled_default.js.map