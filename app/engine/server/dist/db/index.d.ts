import type { Db, DbFactory } from './types.js';
export type { Db, DbFactory } from './types.js';
export declare function getDb(): Db;
export declare function getDefaultDbPath(): string;
export declare function defaultDbFactory(platform?: NodeJS.Platform): DbFactory;
export declare function connectDb(dbPath?: string, opts?: {
    /** Create the parent directory if absent. Default: true. Set false in
     *  environments that do not have a writable local filesystem. */
    ensureDir?: boolean;
    /** Factory that constructs the raw Db connection. Default: better-sqlite3. */
    factory?: DbFactory;
}): Db;
/**
 * Whether the directory holding the database may be restricted to this account.
 *
 * The sidecars can only be covered by the directory: SQLite creates `-wal` and
 * `-shm` on the first write and deletes them on the last clean close, so at
 * startup there is nothing there to chmod. But the directory is also shared
 * state — FREEAPI_DB_PATH may point anywhere — and locking down a directory
 * that is not ours is a worse outage than the leak it prevents. Pointing the DB
 * at `/tmp/freeapi.db` must not chmod 0700 `/tmp`.
 *
 * So the rule is ownership by construction rather than a guess about what is
 * safe. Two cases qualify, and nothing else does:
 *
 *   1. We just created the directory. Nothing else can be living in a directory
 *      that did not exist a moment ago.
 *   2. It is the built-in default data directory, which ships as ours.
 *
 * Case 2 is what covers the installed base: an existing deployment already has
 * `server/data`, so case 1 alone would harden new installs and quietly leave
 * every upgrade behind.
 *
 * An operator who points FREEAPI_DB_PATH at a dedicated directory can opt in
 * with FREEAPI_DB_DIR_HARDENING=1, and one who dislikes the default can opt out
 * with =0. It is a deliberate default-on-where-safe rather than a flag, because
 * hardening that only runs when someone remembers to ask for it is the same
 * class of failure as hardening nobody noticed had stopped running.
 */
export declare function shouldHardenDataDir(dataDir: string, created: boolean, platform?: NodeJS.Platform): boolean;
export declare function initDb(dbPath?: string, opts?: {
    ensureDir?: boolean;
    factory?: DbFactory;
}): Db;
export declare function getUnifiedApiKey(): string;
export declare function regenerateUnifiedKey(): string;
export declare function getSetting(key: string): string | undefined;
export declare function setSetting(key: string, value: string): void;
//# sourceMappingURL=index.d.ts.map