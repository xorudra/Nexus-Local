export declare const TOOL_REJECTION_LIMIT = 3;
export declare const TOOL_REJECTION_WINDOW_MS: number;
export declare const TOOL_BENCH_MS: number;
export declare function toolCapabilityKey(platform: string, modelId: string, endpointScope: string | null | undefined): string;
/** Defer this model for tool requests right now (evidence is already conclusive). */
export declare function benchForTools(key: string, now?: number): void;
/** One tool-carrying request was rejected as a bad request by this model. */
export declare function noteToolRejection(key: string, now?: number): void;
/** The model just served a tool-carrying request: it supports tools after all. */
export declare function clearToolRejections(key: string): void;
export declare function isToolBenched(platform: string, modelId: string, endpointScope: string | null | undefined, now?: number): boolean;
export declare function resetToolCapability(): void;
//# sourceMappingURL=tool-capability.d.ts.map