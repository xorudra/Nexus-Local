import type { Db } from '../db/types.js';
import type { Scheduler } from './scheduler.js';
export interface DbBackupResult {
    ok: boolean;
    target?: string;
    bytes?: number;
    restored?: boolean;
    skipped?: string;
}
export declare function isDbBackupConfigured(): boolean;
/**
 * Split a Hugging Face `/resolve/` download URL into the pieces the commit API
 * needs, or null for anything else.
 *
 * A HF repo serves downloads at `/{type}/{ns}/{repo}/resolve/{rev}/{path}`, but
 * that route is read-only: a PUT to it is answered 404/405 and the blob never
 * lands. Writes go through the commit API instead. Both halves are derived from
 * the one URL the operator configures, so FREEAPI_DB_BACKUP_TARGET stays the
 * plain download URL they can paste into a browser.
 *
 * Models are the type with no prefix segment (`/{ns}/{repo}/resolve/...`);
 * datasets and spaces name themselves. The API path pluralizes the type.
 */
export declare function parseHuggingFaceTarget(target: string): {
    commitUrl: string;
    filePath: string;
} | null;
export declare function restoreDbBackupIfNeeded(dbPath?: string): Promise<DbBackupResult>;
export declare function backupDbNow(db: Db, dbPath?: string): Promise<DbBackupResult>;
export declare function startDbBackupPump(db: Db, scheduler: Scheduler, dbPath?: string): (() => void) | null;
//# sourceMappingURL=db-backup.d.ts.map