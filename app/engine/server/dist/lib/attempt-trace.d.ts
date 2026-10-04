import type { AttemptErrorClass } from './fallback-loop.js';
export type AttemptOutcome = 'ok' | 'committed' | 'client_abort' | AttemptErrorClass;
export interface AttemptTraceRecord {
    ordinal: number;
    platform: string;
    modelId: string;
    keyOrdinal: number;
    keyLabel: string | null;
    outcome: AttemptOutcome;
    startOffsetMs: number;
    durationMs: number;
    errorSummary: string | null;
}
export interface RequestTrace {
    records: AttemptTraceRecord[];
    lastRequestRowId: number | null;
}
export declare function newRequestTrace(): RequestTrace;
export declare function runWithRequestTrace<T>(trace: RequestTrace, fn: () => T): T;
export declare function getRequestTrace(): RequestTrace | undefined;
/** Called by logRequest() after inserting a `requests` row; no-op outside a trace. */
export declare function noteRequestRowId(id: number | bigint): void;
//# sourceMappingURL=attempt-trace.d.ts.map