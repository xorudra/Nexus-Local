import { type RequestTrace } from './attempt-trace.js';
export declare function logRequest(platform: string, modelId: string, keyId: number | null, status: string, inputTokens: number, outputTokens: number, latencyMs: number, error: string | null, ttfbMs?: number | null, requestedModel?: string | null, servedModel?: string | null, caller?: string | null): void;
export declare function persistRequestAttempts(trace: RequestTrace): void;
//# sourceMappingURL=request-log.d.ts.map