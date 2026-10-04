export type ModelWeightOverrides = ReadonlyMap<string, number>;
/** Parse the env var. Pure and exported for tests: unknown keys are dropped,
 *  values must be finite and in [0, 2]. Returns an empty map on any malformed
 *  input (not an object, or unparsable JSON) rather than throwing. */
export declare function parseModelWeightOverrides(raw: string | undefined): Map<string, number>;
/** The active overrides — parsed lazily from the environment on first use and
 *  cached for the life of the process (the env is fixed at boot). */
export declare function getModelWeightOverrides(): ModelWeightOverrides;
/** Test seam: forget the cached parse so a changed env var takes effect. */
export declare function resetModelWeightOverrides(): void;
/** Apply a model's override to a bandit score. `overrides` is injectable for
 *  tests; it defaults to the process-wide parsed map. */
export declare function applyModelWeightOverride(score: number, modelId: string, overrides?: ModelWeightOverrides): number;
/** What `warnOnRoutingOverrideDrift` found. Returned for tests; the caller at
 *  boot only wants the log lines. */
export interface RoutingOverrideDrift {
    /** The variable is set but did not parse into a usable object. */
    malformed: boolean;
    /** Keys present in the JSON but dropped: not a finite number in [0, 2]. */
    rejectedValues: string[];
    /** Keys that parsed fine but match no model_id in the catalog. Always empty
     *  when the catalog has not synced yet — see `warnOnRoutingOverrideDrift`. */
    unknownModels: string[];
}
/**
 * Report `MODEL_ROUTING_OVERRIDES` entries that will never do anything.
 *
 * Every rejection path in this module is deliberately silent so a bad variable
 * can never break boot — but silence is the wrong answer for an operator who
 * has just written one. A typo in a model id, a value of 5, or a stray trailing
 * comma all produce exactly the same observable result as not setting the
 * variable at all: the model keeps its normal score and nothing says why.
 *
 * Log-only, and never throws: an unreadable catalog just skips the model-id
 * check rather than failing a boot over a diagnostic.
 *
 * The unknown-model half is SKIPPED until the catalog has synced at least once.
 * This runs at boot, before startCatalogSync, so on a first run the models table
 * holds only what the migrations seeded (110 rows) against a real catalog of
 * ~460: every override naming one of the ~350 not in the seed would be reported
 * as bogus on exactly the boot an operator is most likely to be reading. A
 * warning that cries wolf on its first outing teaches people to skip the line
 * that would have caught the real typo, so it stays quiet until it can be
 * right. The malformed-JSON and bad-multiplier halves need no catalog and
 * always run.
 */
export declare function warnOnRoutingOverrideDrift(logger?: Pick<Console, 'warn'>): RoutingOverrideDrift | null;
//# sourceMappingURL=model-weight-overrides.d.ts.map