#!/usr/bin/env node
export declare function encryptWith(key: Buffer, text: string): {
    encrypted: string;
    iv: string;
    authTag: string;
};
export declare function decryptWith(key: Buffer, encrypted: string, iv: string, authTag: string): string;
/**
 * Ciphertext stored in dedicated columns: the IV and tag live next to their
 * ciphertext in sibling columns, all TEXT.
 */
interface ColumnGroup {
    kind: 'columns';
    table: string;
    idColumn: string;
    encrypted: string;
    iv: string;
    authTag: string;
    label: string;
}
/**
 * Ciphertext stored as a JSON blob in a single `settings` value, in the shape
 * `JSON.stringify(encrypt(plaintext))` — i.e. `{"encrypted","iv","authTag"}`.
 * The Fetch Relay bearer token is written this way by
 * `encodeFetchRelayToken()` (server/src/lib/proxy.ts) and read back by
 * `decodeFetchRelayToken()`, which degrades to '' with a warning when the
 * value will not decrypt. Miss it here and a rotate silently drops the relay
 * credential on the next restart.
 */
interface SettingGroup {
    kind: 'setting';
    table: 'settings';
    settingKey: string;
    label: string;
}
type EncryptionGroup = ColumnGroup | SettingGroup;
interface RowToRotate {
    group: EncryptionGroup;
    /** Row id for column groups, the settings key for settings blobs. */
    id: number | string;
    plaintext: string;
    reEncrypted: {
        encrypted: string;
        iv: string;
        authTag: string;
    };
}
/** Result of a rotate attempt: rows re-encrypted, or an error that aborted it. */
export interface RotateResult {
    rows: RowToRotate[];
    error?: string;
}
/** The read surface rotateSecrets needs — better-sqlite3 and the app's Db both satisfy it. */
export interface RotateReadDb {
    prepare(sql: string): {
        all(...args: unknown[]): unknown[];
        get(...args: unknown[]): unknown;
    };
}
/** The write surface applyRotation needs, including better-sqlite3's transaction(). */
export interface RotateWriteDb {
    prepare(sql: string): {
        run(...args: unknown[]): unknown;
    };
    transaction<A extends unknown[]>(fn: (...args: A) => void): (...args: A) => unknown;
}
/**
 * Core rotate routine, exported so tests can drive it against an in-memory
 * DB. Decrypts every stored secret with `oldKey` and re-encrypts with
 * `newKey`. Returns `{ rows }` on success and `{ rows: [], error }` when ANY
 * value fails to decrypt — the caller must treat the error case as "nothing
 * written".
 */
export declare function rotateSecrets(db: RotateReadDb, oldKey: Buffer, newKey: Buffer): RotateResult;
/**
 * Apply a rotate result: write every re-encrypted value back to its row, in
 * one transaction. Exported so main() and tests share the exact write path.
 */
export declare function applyRotation(db: RotateWriteDb, rows: RowToRotate[]): void;
export {};
//# sourceMappingURL=rotate-encryption-key.d.ts.map