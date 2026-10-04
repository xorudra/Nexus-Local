export declare const REQUEST_MAX_TOKENS_BUDGET_SETTING = "request_max_tokens_budget";
export declare const MAX_CONSECUTIVE_UPSTREAM_FAILS_SETTING = "max_consecutive_upstream_fails";
/** Per-request token budget ceiling; 0 = disabled. */
export declare function getRequestMaxTokensBudget(): number;
/** Consecutive-upstream-failure breaker threshold; 0 = disabled. */
export declare function getMaxConsecutiveUpstreamFails(): number;
export interface TokenBudgetRejection {
    budget: number;
    estimatedTotal: number;
}
export interface TokenBudgetResult {
    rejection: TokenBudgetRejection | null;
    /** The max_tokens to forward upstream: unchanged when the client set one,
     *  capped to min(budget remainder, TOKEN_BUDGET_OUTPUT_CAP) when it didn't. */
    maxTokens: number | undefined;
}
export declare const TOKEN_BUDGET_OUTPUT_CAP = 4096;
/**
 * Apply the per-request token budget to one request. `estimatedInputTokens`
 * is the surface's existing input estimate (~4 chars/token, images at the
 * flat per-image estimate); `maxTokens` is the client-requested output cap,
 * possibly undefined on the OpenAI-shaped surfaces.
 */
export declare function applyTokenBudget(estimatedInputTokens: number, maxTokens: number | undefined): TokenBudgetResult;
export declare function tokenBudgetMessage(r: TokenBudgetRejection): string;
export interface BreakerState {
    limit: number;
    consecutive: number;
}
export declare function newBreaker(limit?: number): BreakerState;
/**
 * Record one failed upstream attempt. Returns true when the breaker trips
 * (the recorded failure reached the limit). No-op returning false when the
 * guardrail is disabled (limit <= 0).
 */
export declare function recordBreakerFailure(state: BreakerState): boolean;
//# sourceMappingURL=guardrails.d.ts.map