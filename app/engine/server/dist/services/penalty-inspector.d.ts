export type InspectorReason = 'penalty' | 'cooldown' | 'recent_errors';
export interface InspectorRow {
    modelDbId: number | null;
    platform: string;
    modelId: string;
    displayName: string;
    enabled: boolean;
    fallbackEnabled: boolean;
    priority: number | null;
    penalty: {
        hits: number;
        value: number;
        rateLimitFactor: number;
    };
    cooldowns: Array<{
        keyId: number;
        keyLabel: string | null;
        keyStatus: string | null;
        expiresAtMs: number;
        expiresInMs: number;
    }>;
    recentErrors: Array<{
        id: number;
        keyId: number | null;
        keyLabel: string | null;
        error: string;
        latencyMs: number;
        createdAt: string;
    }>;
    recentErrorCount: number;
    reasons: InspectorReason[];
}
export interface PenaltyInspectorSnapshot {
    generatedAtMs: number;
    lookbackMinutes: number;
    rows: InspectorRow[];
}
export interface RouterPressureClearResult {
    /** Active cooldown benches lifted (every key, every model). */
    cooldowns: number;
    /** Models whose score penalty was dropped. */
    penalties: number;
    /** Models whose cross-key failure streak was reset. */
    failureWindows: number;
}
/**
 * The "Clear all" action behind the Router pressure panel (#952). One click
 * releases everything the router accumulated against a pool: cooldowns (and
 * the ladder counters behind them), score penalties, and the model-failure
 * streaks that re-bench a model across keys. Pressure rebuilds from the next
 * live results, so the worst case of a premature clear is one more round of
 * failures — far better than a pool that cannot route for a day.
 */
export declare function clearRouterPressure(): RouterPressureClearResult;
export declare function getPenaltyInspector(): PenaltyInspectorSnapshot;
//# sourceMappingURL=penalty-inspector.d.ts.map