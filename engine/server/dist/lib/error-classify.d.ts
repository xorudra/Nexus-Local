export declare function isRetryableError(err: any): boolean;
/** True when the error — or anything in its bounded cause chain — is a
 * transient network transport failure: a reset, dropped, refused or timed-out
 * socket, a failed TLS handshake, or an undici transport code. */
export declare function isTransportError(err: any): boolean;
export declare function isRateLimitSignal(err: any): boolean;
export declare const TIMEOUT_ERROR_MARKERS: readonly ["timeout", "stalled", "etimedout", "aborted"];
/** True when an error message reads as a timeout. Expects raw text; caller need
 * not lowercase it. */
export declare function isTimeoutErrorText(message: unknown): boolean;
export declare function newClientAbortError(): Error;
/** True when an error is (or wraps) the client-disconnect abort above. The
 * structured marker is the primary signal; `cause` is checked because some
 * transports re-wrap the abort reason, and the message substring is the last
 * resort for errors that were stringified across a boundary. */
export declare function isClientAbortError(err: any): boolean;
export declare function newHedgeAbortError(): Error;
/** True when an error is (or wraps) the time-budget hedge abort above. */
export declare function isHedgeAbortError(err: any): boolean;
/** True for any fetch-abort rejection surfacing out of a body read — the
 * per-attempt timeout ('request'-bounds deadline in fetchWithTimeout), an
 * AbortSignal.timeout, or the client disconnect above. Adapters that wrap
 * res.json() in a diagnostic catch (openai-compat's non-JSON-body split) must
 * rethrow these instead of classifying them as a malformed provider body. */
export declare function isAbortLikeError(err: any): boolean;
export declare function isKeyAuthError(err: any): boolean;
export declare function isDailyQuotaExhaustedError(err: any): boolean;
export declare function isProviderDegradedError(err: any): boolean;
export declare function isProviderLevelError(err: any): boolean;
export declare function isUpstreamClassificationOutput(text: unknown, platform?: string): boolean;
export declare function isProviderBadRequestError(err: any): boolean;
export declare function isContextTooLargeError(err: any): boolean;
export declare function isPaymentRequiredError(err: any): boolean;
export declare function isModelNotFoundError(err: any): boolean;
export declare function isAccountSuspendedError(err: any): boolean;
export declare function isModelAccessForbiddenError(err: any): boolean;
export type ModelRetirementConfidence = 'definitive' | 'probable';
export declare function modelRetirementSignal(err: any): ModelRetirementConfidence | null;
export declare function isStreamTruncatedError(err: any): boolean;
//# sourceMappingURL=error-classify.d.ts.map