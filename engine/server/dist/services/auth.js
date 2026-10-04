import crypto from 'crypto';
import { getDb } from '../db/index.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
// Dashboard authentication: email + password accounts with opaque session
// tokens. Distinct from the unified API key, which authenticates the /v1 proxy
// for apps — this gates the /api/* admin surface for the human operator (#35).
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
function sha256(s) {
    return crypto.createHash('sha256').update(s).digest('hex');
}
/** The one spelling of an address the DB is keyed on. Exported so callers that
 *  bucket by email (the login throttle in routes/auth.ts) key on exactly what
 *  verifyCredentials will look up — keying on anything else lets a padded
 *  address authenticate against the real row while landing in its own bucket. */
export function normalizeEmail(email) {
    return email.trim().toLowerCase();
}
export function userCount() {
    const row = getDb().prepare('SELECT COUNT(*) AS c FROM users').get();
    return row.c;
}
/** Create a user. Throws { code: 'email_taken' } if the email already exists. */
export function createUser(email, password) {
    const db = getDb();
    const normalized = normalizeEmail(email);
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalized);
    if (existing) {
        const err = new Error('An account with that email already exists');
        err.code = 'email_taken';
        throw err;
    }
    const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
        .run(normalized, hashPassword(password));
    return { userId: Number(result.lastInsertRowid), email: normalized };
}
/** Verify credentials. Returns the user on success, null on failure. */
export function verifyCredentials(email, password) {
    const db = getDb();
    const row = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?')
        .get(normalizeEmail(email));
    if (!row)
        return null;
    if (!verifyPassword(password, row.password_hash))
        return null;
    return { userId: row.id, email: row.email };
}
/** Mint a session and return the raw token (only the hash is persisted). */
export function createSession(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    getDb().prepare('INSERT INTO sessions (token_hash, user_id, expires_at_ms) VALUES (?, ?, ?)')
        .run(sha256(token), userId, Date.now() + SESSION_TTL_MS);
    return token;
}
/** Resolve a session token to its user, or null if missing/expired. */
export function validateSession(token) {
    if (!token)
        return null;
    const db = getDb();
    const row = db.prepare(`
    SELECT s.user_id, s.expires_at_ms, u.email
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `).get(sha256(token));
    if (!row)
        return null;
    if (row.expires_at_ms < Date.now()) {
        db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
        return null;
    }
    return { userId: row.user_id, email: row.email };
}
export function deleteSession(token) {
    if (!token)
        return;
    getDb().prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
}
/** Update the email of the authenticated user after verifying the current password. Throws { code: 'email_taken' } on conflict. */
export function updateEmail(userId, currentPassword, newEmail) {
    const db = getDb();
    const row = db.prepare('SELECT password_hash FROM users WHERE id = ?')
        .get(userId);
    if (!row)
        return false;
    if (!verifyPassword(currentPassword, row.password_hash))
        return false;
    const normalized = normalizeEmail(newEmail);
    const existing = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(normalized, userId);
    if (existing) {
        const err = new Error('An account with that email already exists');
        err.code = 'email_taken';
        throw err;
    }
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(normalized, userId);
    // Keep sessions alive; the new email will be reflected on the next validateSession call.
    return true;
}
/** Update the password of the authenticated user after verifying the current one. Invalidates all sessions on success. */
export function updatePassword(userId, currentPassword, newPassword) {
    const db = getDb();
    const row = db.prepare('SELECT password_hash FROM users WHERE id = ?')
        .get(userId);
    if (!row)
        return false;
    if (!verifyPassword(currentPassword, row.password_hash))
        return false;
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), userId);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    return true;
}
/**
 * Reset the password for the single existing user and invalidate all
 * sessions.
 * Returns false if no user exists.
 */
export function resetUserPassword(newPassword) {
    const db = getDb();
    const row = db.prepare('SELECT id FROM users LIMIT 1').get();
    if (!row)
        return false;
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), row.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.id);
    return true;
}
//# sourceMappingURL=auth.js.map