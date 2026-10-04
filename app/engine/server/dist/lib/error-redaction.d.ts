export declare function sanitizeProviderErrorMessage(message: unknown): string;
/**
 * The short per-attempt error summary the failover ladder stores per hop:
 * the same secret/URL redactions as sanitizeProviderErrorMessage, re-capped
 * at 200 chars so the drill-down stays one line per attempt.
 */
export declare function summarizeAttemptError(message: unknown): string;
//# sourceMappingURL=error-redaction.d.ts.map