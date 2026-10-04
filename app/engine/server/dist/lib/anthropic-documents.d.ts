export interface DocumentBlockOk {
    ok: true;
    /** The text block body to substitute for the document block. */
    text: string;
}
export interface DocumentBlockRejected {
    ok: false;
    /** Caller-facing reason, already phrased to slot into an error response. */
    reason: string;
}
export type DocumentBlockResult = DocumentBlockOk | DocumentBlockRejected;
/**
 * A fence tag derived from the CONTENT, as `document-<12 hex>`.
 *
 * Deliberately not random: these blocks can carry `cache_control`, and a
 * per-request nonce would change the prompt prefix on every call and bust the
 * provider's cache for no benefit.
 *
 * Deliberately not the client's title either. A title of `doc>\n</doc` closes
 * the fence early, and everything after it reads to the model as instructions
 * rather than as quoted document text.
 */
export declare function fenceTag(content: string): string;
/**
 * A title safe to echo inside the fence: no control characters, no angle
 * brackets or quotes (they break out of the tag), collapsed whitespace,
 * bounded length.
 */
export declare function labelTitle(raw: unknown): string;
/**
 * Convert one Anthropic `document` block into the text that stands in for it,
 * or explain why it cannot be converted.
 */
export declare function convertDocumentBlock(block: unknown): DocumentBlockResult;
/**
 * The error message for one or more unconvertible documents. Names what was
 * wrong and then what to do instead — a caller that only learns "unsupported"
 * has to guess at the fix.
 */
export declare function documentRejectionMessage(reasons: string[]): string;
//# sourceMappingURL=anthropic-documents.d.ts.map