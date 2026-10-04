#!/usr/bin/env node
/**
 * rotate-encryption-key — re-encrypt every stored secret under a new
 * ENCRYPTION_KEY without losing a single value.
 *
 * Why this exists: AES-256-GCM is authenticated, so a DB carried over to a
 * different ENCRYPTION_KEY fails loudly on the first decrypt — every stored
 * API key, proxy override, client-profile credential and the Fetch Relay
 * token becomes unreadable at once, and there is no recovery path short of
 * re-entering secrets by hand.
 * Rotating keys (compromise, policy expiry, onboarding) therefore has to walk
 * the ciphertext, decrypt each value with the OLD key and re-encrypt it with
 * the NEW one, atomically, before the new key ever becomes active.
 *
 * The cipher parameters deliberately mirror server/src/lib/crypto.ts
 * (aes-256-gcm, 32-byte key hex, 16-byte IV, 16-byte GCM tag) so a value
 * written here decrypts under the running server exactly like one written by
 * `encrypt()`. The script does NOT touch the module-level key cache — it
 * performs every decrypt with `--old-key` and every encrypt with `--new-key`
 * explicitly, so it is safe to run while the server is stopped (recommended)
 * or even live (a writer that fires mid-run sees only already-migrated rows
 * because both keys are valid until the process restarts with the new key).
 *
 * Usage:
 *   tsx src/scripts/rotate-encryption-key.ts --old-key <64hex> --new-key <64hex> [--db <path>] [--dry-run]
 *
 *   --old-key  the current key (hex, 64 chars). Falls back to ENCRYPTION_KEY.
 *   --new-key  the key to rotate to (hex, 64 chars). Required.
 *   --db       SQLite path (default: the server's data/freeapi.db).
 *   --dry-run  decrypt + print every affected row WITHOUT writing anything.
 *
 * Exits 0 on success (or a clean dry run), 1 on any decrypt/validation error.
 * Nothing is written unless EVERY row decrypts — a partial rotate would leave
 * the DB in a mixed-key state that is exactly the failure this script exists
 * to prevent.
 */
import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const ALGORITHM = 'aes-256-gcm';
const KEY_HEX_LEN = 64;
const AUTH_TAG_BYTES = 16;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DB = path.resolve(__dirname, '../../data/freeapi.db');
function arg(name) {
    const i = process.argv.indexOf(`--${name}`);
    return i !== -1 ? process.argv[i + 1] : undefined;
}
function flag(name) {
    return process.argv.includes(`--${name}`);
}
function parseHexKey(value, source) {
    if (value.length !== KEY_HEX_LEN || !/^[0-9a-fA-F]+$/.test(value)) {
        throw new Error(`Invalid key (${source}): expected ${KEY_HEX_LEN} hex chars (32 bytes), got ${value.length} chars. ` +
            `Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`);
    }
    return Buffer.from(value, 'hex');
}
export function encryptWith(key, text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex') };
}
export function decryptWith(key, encrypted, iv, authTag) {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'), { authTagLength: AUTH_TAG_BYTES });
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
// Every place a secret is persisted. Keep this in step with the `encrypt()`
// call sites in server/src/lib/crypto.ts consumers: api_keys (keys.ts,
// custom-endpoint.ts, declarative-config.ts), api_keys proxy columns
// (lib/key-proxy.ts), client_profiles (routes/client-profiles.ts) and the
// settings blob (lib/proxy.ts).
const ENCRYPTION_GROUPS = [
    { kind: 'columns', table: 'api_keys', idColumn: 'id', encrypted: 'encrypted_key', iv: 'iv', authTag: 'auth_tag', label: 'api key' },
    { kind: 'columns', table: 'api_keys', idColumn: 'id', encrypted: 'proxy_encrypted', iv: 'proxy_iv', authTag: 'proxy_auth_tag', label: 'per-key proxy override' },
    { kind: 'columns', table: 'client_profiles', idColumn: 'id', encrypted: 'encrypted_key', iv: 'iv', authTag: 'auth_tag', label: 'client-profile credential' },
    { kind: 'setting', table: 'settings', settingKey: 'fetch_relay_token', label: 'fetch relay token' },
];
/**
 * Core rotate routine, exported so tests can drive it against an in-memory
 * DB. Decrypts every stored secret with `oldKey` and re-encrypts with
 * `newKey`. Returns `{ rows }` on success and `{ rows: [], error }` when ANY
 * value fails to decrypt — the caller must treat the error case as "nothing
 * written".
 */
export function rotateSecrets(db, oldKey, newKey) {
    const rowsToRotate = [];
    for (const group of ENCRYPTION_GROUPS) {
        const cols = db.prepare(`PRAGMA table_info(${group.table})`).all();
        const names = new Set(cols.map((c) => c.name));
        // Ciphertext held as (encrypted, iv, auth_tag) columns.
        if (group.kind === 'columns') {
            if (!names.has(group.encrypted) || !names.has(group.iv) || !names.has(group.authTag)) {
                continue;
            }
            const rows = db.prepare(`SELECT ${group.idColumn} AS id, ${group.encrypted} AS enc, ${group.iv} AS iv, ${group.authTag} AS tag ` +
                `FROM ${group.table} WHERE ${group.encrypted} IS NOT NULL`).all();
            for (const row of rows) {
                let plaintext;
                try {
                    plaintext = decryptWith(oldKey, row.enc, row.iv, row.tag);
                }
                catch (err) {
                    return {
                        rows: [],
                        error: `cannot decrypt ${group.label} #${row.id} with --old-key — wrong key or corrupted ciphertext (${err.message}). Aborting; nothing was written.`,
                    };
                }
                rowsToRotate.push({ group, id: row.id, plaintext, reEncrypted: encryptWith(newKey, plaintext) });
            }
            continue;
        }
        // Ciphertext held as a JSON blob in settings.value.
        if (!names.has('key') || !names.has('value'))
            continue;
        const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(group.settingKey);
        // An unset or cleared setting stores '' rather than a blob — nothing to do.
        if (!row || !row.value)
            continue;
        let parsed;
        try {
            parsed = JSON.parse(row.value);
        }
        catch {
            return {
                rows: [],
                error: `${group.label} (settings.${group.settingKey}) is not valid JSON — refusing to guess. Aborting; nothing was written.`,
            };
        }
        if (!parsed.encrypted || !parsed.iv || !parsed.authTag) {
            return {
                rows: [],
                error: `${group.label} (settings.${group.settingKey}) is missing encrypted/iv/authTag. Aborting; nothing was written.`,
            };
        }
        let plaintext;
        try {
            plaintext = decryptWith(oldKey, parsed.encrypted, parsed.iv, parsed.authTag);
        }
        catch (err) {
            return {
                rows: [],
                error: `cannot decrypt ${group.label} (settings.${group.settingKey}) with --old-key — wrong key or corrupted ciphertext (${err.message}). Aborting; nothing was written.`,
            };
        }
        rowsToRotate.push({ group, id: group.settingKey, plaintext, reEncrypted: encryptWith(newKey, plaintext) });
    }
    return { rows: rowsToRotate };
}
/**
 * Apply a rotate result: write every re-encrypted value back to its row, in
 * one transaction. Exported so main() and tests share the exact write path.
 */
export function applyRotation(db, rows) {
    const write = db.transaction((items) => {
        for (const r of items) {
            if (r.group.kind === 'setting') {
                // Same encoding encodeFetchRelayToken() writes, so the running server
                // reads it back unchanged.
                db.prepare('UPDATE settings SET value = ? WHERE key = ?')
                    .run(JSON.stringify(r.reEncrypted), r.group.settingKey);
                continue;
            }
            db.prepare(`UPDATE ${r.group.table} SET ${r.group.encrypted} = ?, ${r.group.iv} = ?, ${r.group.authTag} = ? WHERE ${r.group.idColumn} = ?`).run(r.reEncrypted.encrypted, r.reEncrypted.iv, r.reEncrypted.authTag, r.id);
        }
    });
    write(rows);
}
function main() {
    const oldKeyHex = arg('old-key') ?? process.env.ENCRYPTION_KEY;
    const newKeyHex = arg('new-key');
    const dbPath = arg('db') ?? DEFAULT_DB;
    const dryRun = flag('dry-run');
    if (!oldKeyHex) {
        console.error('error: --old-key is required (or set ENCRYPTION_KEY)');
        process.exit(1);
    }
    if (!newKeyHex) {
        console.error('error: --new-key is required');
        process.exit(1);
    }
    if (!fs.existsSync(dbPath)) {
        console.error(`error: database not found at ${dbPath}`);
        process.exit(1);
    }
    const oldKey = parseHexKey(oldKeyHex, 'old');
    const newKey = parseHexKey(newKeyHex, 'new');
    if (oldKey.equals(newKey)) {
        console.error('error: --old-key and --new-key are identical — nothing to rotate');
        process.exit(1);
    }
    const db = new Database(dbPath, { readonly: dryRun });
    try {
        const result = rotateSecrets(db, oldKey, newKey);
        if (result.error) {
            console.error(`error: ${result.error}`);
            process.exit(1);
        }
        const rowsToRotate = result.rows;
        if (rowsToRotate.length === 0) {
            console.log('No encrypted values found — nothing to rotate.');
            return;
        }
        if (dryRun) {
            console.log(`[dry-run] would rotate ${rowsToRotate.length} value(s):`);
            for (const r of rowsToRotate) {
                const where = r.group.kind === 'setting' ? `settings.${r.group.settingKey}` : `#${r.id}`;
                console.log(`  ${r.group.label} ${where} -> ${r.plaintext.slice(0, 3)}*** (${r.plaintext.length} chars)`);
            }
            return;
        }
        applyRotation(db, rowsToRotate);
        console.log(`Rotated ${rowsToRotate.length} value(s) to the new key.`);
        console.log('Next steps: set ENCRYPTION_KEY to the new key (or overwrite the .encryption-key file next to the DB) and restart the server.');
    }
    finally {
        db.close();
    }
}
// Only run when invoked directly (`tsx src/scripts/rotate-encryption-key.ts`),
// not when the module is imported by tests for `rotateSecrets`/`encryptWith`.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main();
}
//# sourceMappingURL=rotate-encryption-key.js.map