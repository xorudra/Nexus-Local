import type { Db } from '../types.js';
/**
 * The router prefers the active profile's `profile_models` chain, while the
 * visible Models page historically edited `fallback_config`. New rows added by
 * catalog sync or custom providers were therefore missing from the hidden active
 * profile and never entered auto routing. Backfill every profile with any model
 * rows it lacks, preserving the current fallback_config enabled flag for the
 * initial auto-routing state.
 */
export declare function up(db: Db): void;
export declare function down(db: Db): void;
//# sourceMappingURL=20260714_000001_profile_chain_backfill.d.ts.map