import type { Db } from '../db/types.js';
import type { Scheduler } from '../lib/scheduler.js';
export type BackupSource = 'manual' | 'scheduled' | 'pre-restore';
export interface BackupSchedule {
    enabled: boolean;
    /** Local wall-clock time, HH:mm. */
    time: string;
    /** Minimum days between automatic backups. */
    intervalDays: number;
    /** Optional sub-directory of the database directory; '' means <db-dir>/backups. */
    backupPath: string;
}
export interface BackupMeta {
    id: number;
    filename: string;
    filesize: number;
    isFull: boolean;
    source: BackupSource;
    createdAt: string;
    tables: string[];
}
export declare function isExcludedTable(name: string): boolean;
/** Every table a dump may contain, in a stable order. */
export declare function listTables(db?: Db): string[];
/** Resolve (and create) the directory a dump is written to. `override` is
 *  interpreted relative to the database directory and may not escape it:
 *  an operator-supplied path is otherwise an arbitrary-write primitive, and
 *  `..`, an absolute path or a symlink out of the tree would all take it
 *  there. Both the lexical path and — once the directory exists — its real
 *  path are checked, so a symlink planted inside the data directory does not
 *  widen the hole. */
export declare function resolveBackupDir(db: Db, override?: string): string;
/** Validation hook for the schedule route: reject a path the writer would
 *  refuse later, at the moment the operator types it. */
export declare function assertBackupPathAllowed(db: Db, backupPath: string): void;
export declare function readBackupSchedule(): BackupSchedule;
export declare function writeBackupSchedule(schedule: BackupSchedule): BackupSchedule;
/** Identity of the schema a dump was taken against: the number of applied
 *  migrations plus the latest filename. Restoring a dump into a database at a
 *  different schema silently drops columns added since, or fails halfway; the
 *  header lets restore refuse instead. */
export declare function schemaVersion(db: Db): string;
export declare function createBackup(db: Db, opts?: {
    tables?: string[];
    source?: BackupSource;
    backupPath?: string;
}): BackupMeta;
export declare function listBackups(db: Db, opts?: {
    page?: number;
    pageSize?: number;
}): {
    items: BackupMeta[];
    total: number;
};
export declare function getBackupFile(db: Db, id: number): {
    path: string;
    filename: string;
};
export declare function deleteBackup(db: Db, id: number): void;
export interface RestoreResult {
    backup: BackupMeta;
    /** Dump of the pre-restore state, written before anything was changed. */
    snapshot: BackupMeta;
}
export declare function restoreBackup(db: Db, id: number): RestoreResult;
export declare function startBackupScheduler(scheduler: Scheduler): () => void;
//# sourceMappingURL=backups.d.ts.map