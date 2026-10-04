import type { CompressionMode, CompressionRequestStats } from './types.js';
interface EngineAggregate {
    applied: number;
    discarded: number;
    savedChars: number;
}
export declare function recordCompressionStats(mode: CompressionMode, stats: CompressionRequestStats): void;
export declare function getCompressionStats(): {
    requests: number;
    compressedRequests: number;
    originalChars: number;
    compressedChars: number;
    estSavedTokens: number;
    savingsPercent: number;
    avgDurationMs: number;
    byMode: {
        [k: string]: {
            estSavedTokens: number;
            requests: number;
            savedChars: number;
        };
    };
    engines: {
        [k: string]: EngineAggregate;
    };
};
export declare function clearCompressionStats(): void;
export {};
//# sourceMappingURL=stats.d.ts.map