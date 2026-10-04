import crypto from 'crypto';
import { getDb, getUnifiedApiKey } from '../db/index.js';
import { timingSafeStringEqual } from '../routes/proxy.js';
function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}
export function listUrlTokens() {
    const rows = getDb().prepare(`
    SELECT id, label, token_prefix, created_at, last_used_at, revoked_at
    FROM url_tokens
    ORDER BY id DESC
  `).all();
    return rows.map(row => ({
        id: row.id,
        label: row.label,
        tokenPrefix: row.token_prefix,
        createdAt: row.created_at,
        lastUsedAt: row.last_used_at,
        revokedAt: row.revoked_at,
    }));
}
export function mintUrlToken(label) {
    const token = `flmurl_${crypto.randomBytes(24).toString('base64url')}`;
    const prefix = `${token.slice(0, 12)}…`;
    const result = getDb().prepare(`
    INSERT INTO url_tokens (token_hash, label, token_prefix)
    VALUES (?, ?, ?)
  `).run(hashToken(token), label.trim(), prefix);
    const row = listUrlTokens().find(entry => entry.id === Number(result.lastInsertRowid));
    return { ...row, token };
}
export function revokeUrlToken(id) {
    return getDb().prepare(`
    UPDATE url_tokens SET revoked_at = datetime('now')
    WHERE id = ? AND revoked_at IS NULL
  `).run(id).changes > 0;
}
export function validateUrlToken(token) {
    if (!token || timingSafeStringEqual(token, getUnifiedApiKey())) {
        if (token) {
            console.warn('[URL tokens] Rejected a raw unified API key in a tokenized URL');
        }
        return false;
    }
    const hash = hashToken(token);
    const row = getDb().prepare(`
    SELECT id FROM url_tokens
    WHERE token_hash = ? AND revoked_at IS NULL
  `).get(hash);
    if (!row)
        return false;
    getDb().prepare("UPDATE url_tokens SET last_used_at = datetime('now') WHERE id = ?").run(row.id);
    return true;
}
//# sourceMappingURL=url-tokens.js.map