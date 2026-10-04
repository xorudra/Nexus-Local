import type { Db } from '../types.js';
/**
 * GitHub Models' free GPT-4.1 endpoint rejects requests above the low-tier
 * per-call input cap even though the upstream model can support a larger
 * context elsewhere. Keep the local catalog aligned with the routable limit.
 */
export declare function up(db: Db): void;
export declare function down(db: Db): void;
//# sourceMappingURL=20260630_000001_github_gpt41_context.d.ts.map