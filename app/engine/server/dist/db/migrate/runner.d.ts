import type { Db } from '../types.js';
export type MigrationDirection = 'up' | 'down';
export type MigrationState = 'applied' | 'pending';
export interface MigrationRunnerOptions {
    migrationsDir?: string;
    migrationFileExtension?: '.ts' | '.js';
}
export interface MigrationStatus {
    filename: string;
    status: MigrationState;
    appliedAt: string | null;
}
export declare function runMigrations(db: Db, direction?: MigrationDirection, options?: MigrationRunnerOptions): Promise<void>;
export declare function runMigrationsSync(db: Db, direction?: MigrationDirection): void;
export declare function getMigrationStatuses(db: Db, options?: MigrationRunnerOptions): MigrationStatus[];
//# sourceMappingURL=runner.d.ts.map