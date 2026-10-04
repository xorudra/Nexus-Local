import type { Db } from '../types.js';
/** Metadata index for the data-backup feature. Backup payloads live on disk
 *  next to the database; this table is the paginated index. `filepath` records
 *  the absolute location so download and restore survive a later change to the
 *  configured backup directory. */
export declare function up(db: Db): void;
export declare function down(db: Db): void;
//# sourceMappingURL=20260823_000002_backups_table.d.ts.map