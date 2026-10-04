export declare function providerTimeoutEnvName(platform: string): string;
/** Effective chat timeout for a platform: the PROVIDER_TIMEOUT_<PLATFORM> env
 * override when set and valid, else the built-in default. Returns 0 to mean
 * "no timeout" — callers must skip their abort timer for 0, never schedule
 * setTimeout(0). */
export declare function providerTimeoutMs(platform: string, defaultMs: number): number;
export declare const DEFAULT_STREAM_STALL_TIMEOUT_MS = 90000;
export declare function streamStallTimeoutEnvName(platform: string): string;
/** Effective mid-stream inactivity timeout, 0 disables. Resolved per call so
 * tests can vary the env. Precedence (#584): the per-platform
 * PROVIDER_STREAM_STALL_TIMEOUT_<PLATFORM> when a platform is given and the
 * var is set and valid, else the global PROVIDER_STREAM_STALL_TIMEOUT_MS,
 * else the built-in 90s default. */
export declare function streamStallTimeoutMs(platform?: string): number;
/** Test hook: forget which malformed values have already been warned about. */
export declare function resetTimeoutWarnings(): void;
//# sourceMappingURL=provider-timeout.d.ts.map