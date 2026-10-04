import type { Db } from '../types.js';
/**
 * Tombstones used to mean exactly one thing: "the user deleted this catalog
 * model, keep it deleted across syncs". Issue #634 adds a second, machine-made
 * kind — "the provider retired this model upstream (410 / end of life)" — which
 * disables the row instead of deleting it and carries the upstream wording so
 * the dashboard can say why. `source` keeps the two apart ('user' is the
 * backfill for every pre-existing row); `reason` is the redacted provider text.
 */
export declare function up(db: Db): void;
export declare function down(db: Db): void;
//# sourceMappingURL=20260728_000001_tombstone_provenance.d.ts.map