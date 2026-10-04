export interface OneTimeCode {
    /** Mint a new code, replacing any existing one. Returns the raw code string. */
    generate(): string;
    /** Return the current code, or null if none is active. */
    get(): string | null;
    /** Invalidate the current code. */
    clear(): void;
    /**
     * Constant-time comparison against the active code.
     * Returns false if no code is active or the input is not a matching string.
     */
    matches(provided: unknown): boolean;
}
export declare function createOneTimeCode(): OneTimeCode;
//# sourceMappingURL=one-time-code.d.ts.map