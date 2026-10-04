export type ProtectedKind = 'fenced-code' | 'inline-code' | 'url' | 'path' | 'json-key' | 'number' | 'stack-trace' | 'diff-hunk' | 'key-value' | 'error' | 'constraint';
export interface ProtectedSpan {
    start: number;
    end: number;
    text: string;
    kinds: ProtectedKind[];
}
export declare function mergeProtectedSpans(spans: ProtectedSpan[]): ProtectedSpan[];
export declare function scanProtectedSpans(text: string): ProtectedSpan[];
export declare function transformUnprotectedText(text: string, transform: (part: string) => string): string;
/**
 * Boolean-only fast path: true when any rule matches, WITHOUT collecting,
 * sorting or merging the spans. Equivalent to `scanProtectedSpans(text).length > 0`
 * (none of the rules can match the empty string — every pattern requires at
 * least one character), but it exits on the first hit instead of building the
 * full span list. The per-line callers (toolfilter's `mustKeep`,
 * `protectedLines`, hard-budget, relevance) were paying the full
 * collect + sort + merge cost just to answer a yes/no question; on a
 * 20k-line adversarial payload that is the difference between the
 * compression regression test sitting under and over its budget on slow
 * hardware.
 */
export declare function hasProtectedSpan(text: string): boolean;
export declare function hasProtectedContent(text: string): boolean;
export declare function protectedLines(text: string): string[];
export declare function extractProtectedValues(text: string, kind?: ProtectedKind): string[];
//# sourceMappingURL=preservation.d.ts.map