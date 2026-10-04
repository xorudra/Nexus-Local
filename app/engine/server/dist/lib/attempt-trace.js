// Per-request attempt trace: the durable record of the failover ladder one
// proxied request walked (groq 429 → google timeout → cerebras ok). The
// fallback loop collects one AttemptTraceRecord per dispatched attempt —
// including the SUCCESSFUL final one — and request-log.ts persists the batch
// into `request_attempts`, keyed to the terminal `requests` row.
//
// The trace travels on AsyncLocalStorage (same pattern as client-context.ts)
// so logRequest() can report back the id of each `requests` row it writes
// without threading a parameter through every surface's dispatch closure.
// The LAST id noted during a loop run is the terminal row — the success row,
// a committed mid-stream error row, or the final per-attempt failure row —
// and that is the row the batch is keyed to. Calls to logRequest outside a
// fallback-loop run (fusion sub-calls, embeddings, media) see no trace and
// are unaffected.
import { AsyncLocalStorage } from 'async_hooks';
const storage = new AsyncLocalStorage();
export function newRequestTrace() {
    return { records: [], lastRequestRowId: null };
}
export function runWithRequestTrace(trace, fn) {
    return storage.run(trace, fn);
}
export function getRequestTrace() {
    return storage.getStore();
}
/** Called by logRequest() after inserting a `requests` row; no-op outside a trace. */
export function noteRequestRowId(id) {
    const trace = storage.getStore();
    if (trace)
        trace.lastRequestRowId = Number(id);
}
//# sourceMappingURL=attempt-trace.js.map