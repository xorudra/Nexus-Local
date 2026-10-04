/**
 * The dashboard's server-log store.
 *
 * Operators debugging a routing decision, a benched key or a retired model have
 * had exactly one place to look: the terminal the process was started from. On
 * a desktop install, a container, or a systemd unit that is either awkward or
 * gone entirely. This module keeps the same lines the server already prints and
 * makes them readable from the dashboard.
 *
 * Two tiers, ONE id space:
 *   - a ring buffer (RING_CAPACITY entries, every level) backs the live view
 *     and is the only thing the polling endpoint reads;
 *   - warn/error rows are ALSO written to the `server_logs` table, so the
 *     lines that matter survive a restart.
 *
 * Ids are assigned here, not by SQLite, because the client polls with a
 * `sinceId` cursor and that cursor has to mean the same thing for a line that
 * only ever lived in memory and for one that came back from the table. The
 * counter is seeded from MAX(id) at init, so ids keep increasing across
 * restarts and a cursor held by an open dashboard tab never goes backwards.
 *
 * Capture is a TAP inside lib/log-redaction.ts rather than a second console
 * wrapper: there is exactly one console patch in this process, it redacts
 * first, and this store only ever sees the redacted form.
 */
/** Levels the store understands. console.log maps to 'info'; debug and trace
 *  keep their own identity so a noisy trace can be filtered out on its own. */
export declare const LOG_LEVELS: readonly ["trace", "debug", "info", "warn", "error"];
export type ServerLogLevel = (typeof LOG_LEVELS)[number];
/** Live-view depth. A thousand lines is a few minutes of a busy gateway and
 *  costs well under a megabyte at the message cap below. */
export declare const RING_CAPACITY = 1000;
/** How much persisted history is pulled back into the ring at init, so the
 *  dashboard shows the warnings that preceded the restart instead of an empty
 *  panel that fills up only if something goes wrong again. */
export declare const PRELOAD_LIMIT = 200;
/** A single log line is a diagnostic, not a document. Long provider bodies and
 *  multi-frame stacks are truncated rather than dropped — the head is where the
 *  information is. */
export declare const MAX_MESSAGE_LENGTH = 6000;
/**
 * Ceiling on warn/error rows written per second. The table is pruned only on
 * the request path, so an idle server has no retention at all; a log storm (a
 * dead stdout feeding the safety net, a provider erroring in a tight loop) must
 * not be able to grow it without bound. Lines over the cap still reach the live
 * ring — only the row is skipped — and the next line after the window rolls
 * writes one summary row saying how many were dropped.
 */
export declare const PERSIST_MAX_PER_SECOND = 50;
export interface ServerLogMeta {
    provider?: string;
    model?: string;
    event?: string;
    requestId?: string;
}
export interface ServerLogEntry extends ServerLogMeta {
    id: number;
    tsMs: number;
    level: ServerLogLevel;
    /** The `[Tag]` a line opens with, when it has one ('Health', 'CooldownProbe'…). */
    source?: string;
    message: string;
}
export declare function formatLogArgs(args: readonly unknown[]): string;
export interface RecordLogOptions extends ServerLogMeta {
    level: ServerLogLevel;
    message: string;
    source?: string;
    tsMs?: number;
}
/**
 * The single ingest point. Everything — the console tap, providerLog, the boot
 * preload's live siblings — arrives here, which is what makes the noise filter,
 * the length cap and the id counter impossible to bypass.
 *
 * Returns the stored entry, or null when the line was filtered out.
 */
export declare function recordLogEntry(options: RecordLogOptions): ServerLogEntry | null;
/**
 * Called by the console wrapper in lib/log-redaction.ts, AFTER redaction. Never
 * throws: a log line must not be able to fail the call that emitted it.
 */
export declare function recordConsoleLine(level: ServerLogLevel, args: readonly unknown[]): void;
/**
 * Emit a structured operational event: recorded with its provider/model/event
 * metadata for the dashboard AND mirrored to stdout, so nothing an operator
 * needs exists only behind a login.
 *
 * The message is passed through redactSecrets() here because the recording
 * bypasses the console wrapper; the stdout mirror goes through the wrapped
 * console (already-redacted text is idempotent under a second pass) so that a
 * restored console — tests, an embedder — still sees the line.
 */
export declare function providerLog(level: ServerLogLevel, message: string, meta?: ServerLogMeta): void;
/** Force the seed/preload now (the route calls this so an idle server still
 *  shows persisted history on the first poll). */
export declare function initServerLogs(): void;
/** Counts over the CURRENT ring, unfiltered, so the UI can render level badges
 *  without fetching every entry. Trace is folded into debug: it is a debug-tier
 *  detail and the dashboard shows four badges. */
export interface LogLevelCounts {
    debug: number;
    info: number;
    warn: number;
    error: number;
}
export interface LogQuery {
    levels?: ServerLogLevel[];
    q?: string;
    provider?: string;
    sinceId?: number;
    limit?: number;
}
export declare const DEFAULT_LIMIT = 200;
export declare const MAX_LIMIT = 500;
export declare const MIN_LIMIT = 1;
export declare function clampLimit(raw: number | undefined): number;
/** Highest id handed out so far — what the client sends back as sinceId, even
 *  when every entry it would have matched was filtered away. */
export declare function currentMaxId(): number;
export declare function levelCounts(): LogLevelCounts;
/** The newest `limit` entries of the filtered set, oldest→newest. */
export declare function queryLogs(query?: LogQuery): ServerLogEntry[];
/** Empty both tiers. The id counter is deliberately NOT reset: a dashboard tab
 *  holding a cursor would otherwise be handed ids it has already seen. */
export declare function clearLogs(): void;
/** Test seam: drop every entry AND the counter/seed state, so a suite can
 *  simulate a cold start against a database that still holds rows. */
export declare function resetServerLogsForTest(): void;
/** Test/introspection seam: the ring exactly as stored. */
export declare function ringSnapshot(): readonly ServerLogEntry[];
//# sourceMappingURL=server-logs.d.ts.map