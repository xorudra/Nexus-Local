import type { Db } from '../types.js';
export declare function up(db: Db): void;
/** Put back the generic label on every custom endpoint that currently carries
 *  exactly its own host, which is the set `up` could have produced. */
export declare function down(db: Db): void;
//# sourceMappingURL=20260802_000001_custom_endpoint_host_labels.d.ts.map