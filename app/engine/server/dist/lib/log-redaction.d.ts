/**
 * Console-level credential redaction.
 *
 * Provider keys reach stdout through many paths that no single call site owns:
 * a provider adapter logging a failed URL, an undici error whose stack embeds
 * the request, a debug line someone adds during triage. Users routinely paste
 * that output into GitHub issues. Patching console once at boot is the only
 * place that covers every path, including code that has not been written yet.
 *
 * Distinct from lib/error-redaction.ts, which sanitises a single provider error
 * string for API responses: that one also strips every URL and truncates to 240
 * chars, which would make server logs unreadable. This module removes
 * credentials and nothing else.
 *
 * This is also the capture point for the dashboard's server-log viewer
 * (lib/server-logs.ts). The tap lives inside the one wrapper installed below
 * rather than in a second one, so a line is redacted before anything else can
 * see it and the two consumers cannot drift apart.
 */
/** Strip credentials from a string. Safe to call on anything; non-strings are
 *  returned unchanged by the caller, not here. */
export declare function redactSecrets(input: string): string;
/**
 * Wrap the console writers so no provider credential reaches stdout. Idempotent,
 * and must run before anything else logs. Returns a restore function for tests.
 */
export declare function installLogRedaction(): () => void;
//# sourceMappingURL=log-redaction.d.ts.map