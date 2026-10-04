export interface MonthlyBudgetCaps {
    /** 0 = unlimited (the default, unchanged behaviour). */
    requestCap: number;
    /** 0 = unlimited. */
    tokenCap: number;
}
export interface MonthlyUsage {
    /** Successful requests in the current UTC month. */
    requests: number;
    /** Sum of (input_tokens + output_tokens) over those successes. */
    tokens: number;
}
export type BudgetVerdict = {
    allowed: true;
} | {
    allowed: false;
    reason: 'monthly_request_cap' | 'monthly_token_cap';
    retryAfterSec: number;
};
export declare function getMonthlyBudgetCaps(keyId: number): MonthlyBudgetCaps;
export declare function setMonthlyBudgetCaps(keyId: number, patch: Partial<MonthlyBudgetCaps>): boolean;
export declare function getMonthlyUsage(keyId: number, now?: number): MonthlyUsage;
/**
 * Check a key against its monthly caps, taking the current month's successful
 * usage plus the tokens THIS request would add. Returns allowed when both caps
 * are 0 (unlimited) or neither would be exceeded.
 */
export declare function checkMonthlyBudget(keyId: number, estimatedTokens: number, now?: number): BudgetVerdict;
/** Check and reserve synchronously before dispatch; release on every terminal path. */
export declare function reserveMonthlyBudget(keyId: number, estimatedTokens: number): {
    allowed: true;
    release: () => void;
} | Extract<BudgetVerdict, {
    allowed: false;
}>;
/** Seconds from `now` until the next UTC month boundary — the Retry-After value. */
export declare function secondsUntilNextMonth(now?: number): number;
/** ISO timestamp of the next UTC month boundary (for headers / diagnostics). */
export declare function nextMonthResetAt(now?: number): string;
//# sourceMappingURL=key-budget.d.ts.map