export declare function normalizeModelIdForDrift(id: string): string;
/** Test hook: clear the once-per-tuple warn cache. */
export declare function resetServedModelObservations(): void;
/**
 * Compare the raw upstream-reported model against the routed id.
 * Returns the raw served id when it GENUINELY differs (persist it), or null
 * when it matches, differs only cosmetically, or names no model at all
 * (store NULL — keeps the requests table small). Logs a structured warn once
 * per (platform, requested, served) tuple per process.
 */
export declare function observeServedModel(opts: {
    platform: string;
    requestedModel: string;
    servedModel: string | null | undefined;
}): string | null;
//# sourceMappingURL=served-model.d.ts.map