import type { DbFactory } from './types.js';
/**
 * `node:sqlite` adapter used on Android, where better-sqlite3 does not publish
 * prebuilt binaries. It exposes only the small synchronous database contract
 * the server uses and implements better-sqlite3-style nested transactions with
 * savepoints.
 */
export declare const nodeSqliteFactory: DbFactory;
//# sourceMappingURL=node-sqlite.d.ts.map