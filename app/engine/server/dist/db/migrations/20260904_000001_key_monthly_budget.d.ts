import type { Db } from '../types.js';
/**
 * Per-key monthly budget (#1158): optional request / token caps per api_keys
 * row, counted against the current UTC month's SUCCESSFUL requests. 0 means
 * "no cap" — the pre-existing behaviour, so existing installs are untouched.
 *
 * The columns live on api_keys (the operator-facing budget subject), matching
 * the per-key vocabulary already used for daily limits in ratelimit.ts; the
 * month is derived from requests.created_at (UTC), never wall-clock local.
 */
export declare function up(db: Db): void;
export declare function down(db: Db): void;
//# sourceMappingURL=20260904_000001_key_monthly_budget.d.ts.map