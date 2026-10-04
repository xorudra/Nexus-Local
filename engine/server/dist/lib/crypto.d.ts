import type { Db } from '../db/types.js';
/**
 * Initialize encryption key from env or an explicit local-dev fallback.
 * Must be called after DB is initialized.
 *
 * Precedence (dev fallback): ENCRYPTION_KEY env > existing key file next to the
 * DB > legacy `settings` table row (migrated to the file, then deleted) >
 * freshly generated key written to the file.
 */
export declare function initEncryptionKey(db: Db): void;
/**
 * A short, non-reversible identifier for the key currently in use.
 *
 * Database dumps record it in their header so a restore can tell, before it
 * touches a row, whether the api_keys ciphertext in the file was written under
 * this key. sha256 truncated to 64 bits: enough to catch a different key,
 * nowhere near enough to help recover the key itself, and safe to show in an
 * error message or write to a file an operator emails around.
 *
 * Returns null before initEncryptionKey() has run.
 */
export declare function encryptionKeyFingerprint(): string | null;
export declare function isEncryptionKeyInitialized(): boolean;
export declare function encrypt(text: string): {
    encrypted: string;
    iv: string;
    authTag: string;
};
export declare function decrypt(encrypted: string, iv: string, authTag: string): string;
export declare function maskKey(key: string): string;
//# sourceMappingURL=crypto.d.ts.map