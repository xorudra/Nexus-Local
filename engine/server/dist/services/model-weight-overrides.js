import { getDb, getSetting } from '../db/index.js';
// Written by catalog-sync on every completed run (services/catalog-sync.ts).
// Its presence is the only "the catalog is real, not just the migration seed"
// signal available at boot.
const CATALOG_LAST_SYNC_SETTING = 'catalog_last_sync_ms';
/** Overrides parsed from `MODEL_ROUTING_OVERRIDES`, cached after first read. */
let cache = null;
/** Parse the env var. Pure and exported for tests: unknown keys are dropped,
 *  values must be finite and in [0, 2]. Returns an empty map on any malformed
 *  input (not an object, or unparsable JSON) rather than throwing. */
export function parseModelWeightOverrides(raw) {
    if (raw === undefined || raw.trim() === '')
        return new Map();
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        return new Map();
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed))
        return new Map();
    const out = new Map();
    for (const [modelId, value] of Object.entries(parsed)) {
        if (!modelId.trim())
            continue;
        if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 2)
            continue;
        out.set(modelId, value);
    }
    return out;
}
/** The active overrides — parsed lazily from the environment on first use and
 *  cached for the life of the process (the env is fixed at boot). */
export function getModelWeightOverrides() {
    if (cache === null)
        cache = parseModelWeightOverrides(process.env.MODEL_ROUTING_OVERRIDES);
    return cache;
}
/** Test seam: forget the cached parse so a changed env var takes effect. */
export function resetModelWeightOverrides() {
    cache = null;
}
/** Apply a model's override to a bandit score. `overrides` is injectable for
 *  tests; it defaults to the process-wide parsed map. */
export function applyModelWeightOverride(score, modelId, overrides = getModelWeightOverrides()) {
    const override = overrides.get(modelId);
    return override === undefined ? score : score * override;
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
export function warnOnRoutingOverrideDrift(logger = console) {
    const raw = process.env.MODEL_ROUTING_OVERRIDES;
    if (raw === undefined || raw.trim() === '')
        return null;
    const drift = { malformed: false, rejectedValues: [], unknownModels: [] };
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch (err) {
        drift.malformed = true;
        logger.warn(`[config] MODEL_ROUTING_OVERRIDES is not valid JSON and is being ignored entirely `
            + `(${err?.message ?? err}). Expected an object like {"gpt-4o": 0.2}.`);
        return drift;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        drift.malformed = true;
        logger.warn('[config] MODEL_ROUTING_OVERRIDES must be a JSON object mapping model ids to multipliers, '
            + 'e.g. {"gpt-4o": 0.2} — the current value is being ignored entirely.');
        return drift;
    }
    const accepted = parseModelWeightOverrides(raw);
    for (const [modelId, value] of Object.entries(parsed)) {
        if (!modelId.trim() || accepted.has(modelId))
            continue;
        drift.rejectedValues.push(modelId);
        logger.warn(`[config] MODEL_ROUTING_OVERRIDES entry "${modelId}" was dropped: `
            + `${JSON.stringify(value)} is not a finite multiplier in [0, 2].`);
    }
    if (accepted.size > 0) {
        try {
            // Read-only, and gated on a completed sync: before the first one the
            // models table is just the migration seed, so "unknown" would mean
            // "not seeded yet" rather than "wrong".
            if (getSetting(CATALOG_LAST_SYNC_SETTING)) {
                const known = new Set(getDb().prepare('SELECT DISTINCT model_id FROM models').all()
                    .map(r => r.model_id));
                for (const modelId of accepted.keys()) {
                    if (known.has(modelId))
                        continue;
                    drift.unknownModels.push(modelId);
                    logger.warn(`[config] MODEL_ROUTING_OVERRIDES names "${modelId}", which is not a model id in this `
                        + "install's catalog, so the override is not applying. Overrides match model_id alone, "
                        + 'unqualified by platform, and the match is exact and case-sensitive. A model gated '
                        + 'behind a provider you have no key for appears once that key is added.');
                }
            }
        }
        catch {
            // Catalog unreadable (DB not ready, mid-migration). The value half of the
            // report is still useful; skip the existence check rather than throw.
        }
    }
    return drift;
}
//# sourceMappingURL=model-weight-overrides.js.map