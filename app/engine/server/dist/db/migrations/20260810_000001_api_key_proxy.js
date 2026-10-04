/**
 * Per-key proxy override (#590): a key can carry its own proxy URL
 * (http/https/socks4/socks4a/socks5/socks5h) so the same provider can be
 * reached from different exit IPs while the global proxy stays the default.
 *
 * The URL is stored ENCRYPTED, not as plain text: a proxy URL routinely
 * embeds `user:pass@` credentials, which are exactly as sensitive as the API
 * key sitting in the same row — storing them in the clear next to an
 * AES-encrypted key would hand anyone who copied the DB a working set of
 * proxy credentials. So it mirrors the key's own storage: ciphertext + iv +
 * auth tag from lib/crypto.ts (AES-256-GCM). All three columns NULL = no
 * per-key override (the API surface spells that as '').
 */
const COLUMNS = ['proxy_encrypted', 'proxy_iv', 'proxy_auth_tag'];
function hasColumn(db, table, column) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    return columns.some((candidate) => candidate.name === column);
}
export function up(db) {
    for (const column of COLUMNS) {
        if (!hasColumn(db, 'api_keys', column)) {
            db.prepare(`ALTER TABLE api_keys ADD COLUMN ${column} TEXT`).run();
        }
    }
}
export function down(db) {
    for (const column of COLUMNS) {
        if (hasColumn(db, 'api_keys', column)) {
            db.prepare(`ALTER TABLE api_keys DROP COLUMN ${column}`).run();
        }
    }
}
//# sourceMappingURL=20260810_000001_api_key_proxy.js.map