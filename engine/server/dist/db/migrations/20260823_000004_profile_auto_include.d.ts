import type { Db } from '../types.js';
/** Per-chain opt-out from the catalog-sync backfill (#895).
 *
 *  Every profile used to be a copy of the whole catalog, and `ensureAllModelsInProfiles`
 *  put each newly synced model into every profile. That is right for a chain
 *  the user never pruned, and wrong for one they curated by hand: the next
 *  catalog sync silently pushed a dozen models back into it.
 *
 *  1 (the default, and what every existing chain gets) keeps the old behaviour.
 *  A chain created with `empty: true` starts at 0, so it only ever holds what
 *  the user put in it. */
export declare function up(db: Db): void;
export declare function down(db: Db): void;
//# sourceMappingURL=20260823_000004_profile_auto_include.d.ts.map