export declare const GEMINI_FAMILIES: readonly ["default", "pro", "flash", "flashLite"];
export type GeminiFamily = (typeof GEMINI_FAMILIES)[number];
export type GeminiModelMap = Record<GeminiFamily, string>;
export declare function getGeminiModelMap(): GeminiModelMap;
export declare function setGeminiModelMap(input: unknown): GeminiModelMap;
export declare function classifyGeminiFamily(model?: string): GeminiFamily | null;
/**
 * Resolve a Gemini-family request to the operator's selected catalog id.
 * Returning `auto` leaves routing unpinned; concrete non-Gemini catalog ids
 * still pass through unchanged for native clients that select the gateway's
 * advertised ids.
 */
export declare function resolveGeminiModel(model?: string): string;
//# sourceMappingURL=gemini-map.d.ts.map