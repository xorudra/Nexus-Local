import type { Db } from '../db/types.js';
export declare function recordCustomModelTombstone(db: Db, endpointScope: string, modelId: string): void;
export declare function isCustomModelTombstoned(db: Db, endpointScope: string, modelId: string): boolean;
export declare function clearCustomModelTombstone(db: Db, endpointScope: string, modelId: string): void;
//# sourceMappingURL=custom-model-tombstone.d.ts.map