import { type RoutingStrategy, type RoutingWeights, type KeySelectionStrategy, type PeakHoursConfig } from './scoring.js';
import type { BaseProvider } from '../providers/base.js';
import type { Db } from '../db/types.js';
export declare function formatResetEta(soonestResetMs: number | null | undefined, now?: number): string | null;
export declare function summarizeExhaustion(diag: string[] | undefined, soonestResetMs?: number | null, now?: number, keylessSkipped?: number): string;
export interface ChainRow {
    model_db_id: number;
    priority: number;
    enabled: number;
    platform: string;
    model_id: string;
    display_name: string;
    intelligence_rank: number;
    size_label: string;
    monthly_token_budget: string;
    rpm_limit: number | null;
    rpd_limit: number | null;
    tpm_limit: number | null;
    tpd_limit: number | null;
    supports_vision: number;
    supports_tools: number;
    context_window: number | null;
    key_id: number | null;
    endpoint_scope: string;
    /**
     * Ordering TIER, ahead of score. 0 (the default, and what every other chain
     * builder produces) is a normal candidate. A higher number is a fallback that
     * may only serve once every lower tier is exhausted, however good its live
     * numbers are — currently set only for a member reached through a group's
     * auto-derived slug rather than the model id the client actually wrote, where
     * answering on score alone would be a silent substitution (#651).
     */
    match_tier?: number;
}
export interface RouteResult {
    provider: BaseProvider;
    modelId: string;
    modelDbId: number;
    apiKey: string;
    keyId: number;
    /**
     * The operator-assigned api_keys.label for this key at route time (#869),
     * null when the key is unlabeled (the column defaults to ''). Deliberately
     * the human label, never the key id and never the credential: it is what the
     * failover ladder can show without leaking either.
     */
    keyLabel: string | null;
    platform: string;
    displayName: string;
    contextWindow: number | null;
    /**
     * The custom endpoint this route belongs to, '' for catalog platforms (#651).
     * Carried on the route so the failure path can attribute a retirement signal
     * to ONE relay instead of every relay serving the same model id.
     */
    endpointScope: string;
    /**
     * This key's own proxy URL, already decrypted, '' when it has none (#590).
     *
     * It rides the route rather than being looked up at dispatch time on
     * purpose: selectKeyForModel already reads the whole api_keys row and
     * already decrypts on it, so the override costs one extra AES-GCM open per
     * ROUTE — not a prepared SELECT plus a decrypt per ATTEMPT, on the hot path
     * of every request. Optional so test doubles and any future construction
     * path simply mean "no override".
     */
    proxyUrl?: string;
    rpdLimit: number | null;
    tpdLimit: number | null;
    /**
     * Frees the in-flight lease taken when this route was selected. Idempotent.
     *
     * Callers should invoke it once the attempt is finished, however it finished —
     * the shared fallback loop does so from a `finally` so no exit path can leak.
     *
     * Optional, and every call site uses `release?.()`, for a specific reason: the
     * invocation sits in a `finally`, and a TypeError thrown there would *replace*
     * the in-flight provider exception with a useless one, turning a diagnosable
     * 429 into a mystery 500. A route that arrives without it (a test double, a
     * future construction path) should quietly fall back to the lease ageing out
     * rather than destroy the error being propagated.
     */
    release?: () => void;
}
export declare const OUTPUT_RESERVE_CAP = 2000;
/**
 * Output tokens to reserve for routing/filter purposes: the requested max_tokens
 * clamped to OUTPUT_RESERVE_CAP (default 1000 when the client omitted it, matching
 * the historical fallback). Callers add this to their INPUT estimate before
 * calling routeRequest / routePinnedModel.
 */
export declare function routingReserveTokens(requestedMaxTokens: number | null | undefined): number;
/**
 * Record an upstream failure for a model — increases its penalty so it sinks in
 * priority. Default weight is the LIGHT one for ordinary upstream failures
 * (5xx/timeout/empty stream, +1); callers that know they saw a hard limit
 * signal (429/402) pass the heavier weight — a quota limit is the stronger,
 * longer-lived health cue.
 */
export declare function recordModelFailure(modelDbId: number, weight?: number): void;
/**
 * Record a 429 for a model — heavier penalty (priority demotion) than ordinary
 * failures, since a rate-limit signal is the strongest short-term health cue.
 */
export declare function recordRateLimitHit(modelDbId: number): void;
/**
 * Record a success for a model — reduces its penalty so it rises back up.
 */
export declare function recordSuccess(modelDbId: number): void;
/**
 * Get current penalties for all models (for the API/dashboard).
 */
export declare function getAllPenalties(): Array<{
    modelDbId: number;
    count: number;
    penalty: number;
}>;
/**
 * Operator clear (#952): forget every model's penalty at once and report how
 * many models were carrying one. Pairs with clearAllCooldowns — a pool stuck
 * behind day-long benches also has its models sunk by penalties, and lifting
 * one without the other leaves the router still avoiding them.
 */
export declare function clearAllPenalties(): number;
export declare const HEADROOM_RAMP_START_KEY = "routing_headroom_ramp_start";
export declare const HEADROOM_FLOOR_KEY = "routing_headroom_floor";
export declare function getHeadroomThresholds(): {
    rampStart: number | undefined;
    floor: number | undefined;
};
export declare function setHeadroomThresholds(rampStart?: number | null, floor?: number | null): void;
export declare const TASK_WEIGHT_SHARE_KEY = "routing_task_weight_share";
export declare function getTaskWeightShare(): number;
export declare function setTaskWeightShare(value: number | null): void;
/** Chance per request that an unmeasured model gets tried first when the
 *  exploration toggle is on. The bandit's Thompson sampling already explores
 *  automatically; this guarantees a floor so models with no reliability/speed
 *  data still get sampled instead of being starved by prior-heavy rivals. */
export declare const EXPLORE_CHANCE = 0.1;
/** A model counts as "has data" once its decay-weighted success+failure
 *  pseudo-count reaches this many samples. */
export declare const EXPLORE_MIN_SAMPLES = 5;
export declare function getRoutingStrategy(): RoutingStrategy;
export declare function setRoutingStrategy(strategy: RoutingStrategy): void;
export declare function getExploreEnabled(): boolean;
export declare function setExploreEnabled(enabled: boolean): void;
export declare function getPeakHoursConfig(): PeakHoursConfig;
/** Persist any subset of the peak-hours settings. Throws on an out-of-range
 *  hour or an unknown IANA timezone so a bad PUT is rejected at the API rather
 *  than silently stored and then ignored on read. */
export declare function setPeakHoursConfig(patch: Partial<PeakHoursConfig>): void;
export declare const DEFAULT_KEY_SELECTION: KeySelectionStrategy;
export declare function getKeySelectionStrategy(): KeySelectionStrategy;
export declare function setKeySelectionStrategy(strategy: KeySelectionStrategy): void;
export declare function getCustomWeights(): RoutingWeights;
export declare function setCustomWeights(weights: RoutingWeights): void;
type CommunityPriorMap = Record<string, {
    successes: number;
    failures: number;
}>;
/** Ceiling on a single prior's effective sample size. Local counts are
 *  decay-weighted (2-day half-life — a busy install still only carries on the
 *  order of a hundred effective samples), so an unbounded, undecayed community
 *  count would drown local evidence forever and collapse the Thompson-sampling
 *  variance to zero. Capping at ~50 pseudo-observations keeps a prior worth
 *  roughly half the local evidence at most: enough to seed a brand-new model,
 *  cheap for real local traffic to override. */
export declare const COMMUNITY_PRIOR_MAX_SAMPLES = 50;
/** Whether stored community priors are folded into the posterior. Default off. */
export declare function getCommunityPriorEnabled(): boolean;
export declare function setCommunityPriorEnabled(enabled: boolean): void;
/** Community prior for one model, or undefined when none is stored.
 *  Raw read — ignores the enabled flag; routing goes through
 *  activeCommunityPrior, which honors it. */
export declare function getCommunityPrior(platform: string, modelId: string, endpointScope?: string): {
    successes: number;
    failures: number;
} | undefined;
/** Replace the whole community-prior map (e.g. after an aggregation fetch).
 *  Invalid entries are dropped and oversized ones capped, never stored raw. */
export declare function setCommunityPriors(priors: CommunityPriorMap): number;
/** The weight vector routing will use right now for the active strategy, and
 *  whether the peak-hours adjustment moved it. Cheap (settings reads only) —
 *  for the PUT /routing echo, which must not pay for a full score sweep. */
export declare function getActiveRoutingWeights(): {
    weights: RoutingWeights | null;
    adjusted: boolean;
};
export declare function refreshStatsCache(db: Db, force?: boolean): void;
export declare const SPEED_RANK_MIN_SAMPLES = 20;
/** Test hook: forget when the last writeback ran so the next refresh does one. */
export declare function resetSpeedRankWriteback(): void;
/**
 * Write an observed speed rank for every model with enough recent samples and
 * no user-set speed_rank override. Returns how many rows actually changed.
 * Reads the stats cache as-is — callers refresh it first (refreshStatsCache
 * calls this from its own tail).
 */
export declare function writeObservedSpeedRanks(db: Db): number;
/**
 * Route a request to the best available model.
 *
 * Ordering depends on the configured strategy (see orderChain). Everything
 * downstream — key round-robin, cooldowns, token pre-checks, custom base_url
 * resolution, vision filtering, sticky sessions — is strategy-independent.
 *
 * If preferredModelDbId is set, that model gets tried FIRST (sticky sessions).
 * This prevents hallucination from model switching mid-conversation.
 *
 * @param estimatedTokens - estimated total tokens for rate limit check
 * @param skipKeys - set of "platform:modelId:keyId" to skip (failed on this request)
 * @param preferredModelDbId - try this model first (sticky session)
 * @param requireVision - only consider models that accept image input (#118)
 * @param requireTools - only consider models that emit structured tool_calls
 * @param skipPlatforms - platforms ruled out for the rest of this request (#788)
 */
export interface ResolvedChain {
    chain: ChainRow[];
    strategyKey: string;
}
export declare function resolveRoutingChain(modelString: string | undefined): ResolvedChain;
/**
 * Whether the model still has ANOTHER key that could serve it right now, given
 * the key that just failed (excludingKeyId) and any keys already ruled out this
 * request (skipKeys, in the "platform:modelId:keyId" form). Applies the same
 * gates selectKeyForModel uses — enabled + healthy status, not on cooldown,
 * under the provider daily cap, and under rpm/rpd/tpm/tpd — so the answer means
 * "a real, dispatchable alternative exists".
 *
 * Used by the retry loops to decide whether a single key's 429 should demote the
 * WHOLE model (the model-level 429 penalty). It should not: the per-key cooldown
 * already isolates the failing key, so demoting the model while a sibling key can
 * still serve it wrongly sinks a healthy model in the scorer (#454). We only
 * record the model-level hit when this returns false — i.e. the 429 exhausted the
 * model, not just one of its keys.
 */
export declare function hasOtherUsableKey(modelDbId: number, excludingKeyId: number, skipKeys?: Set<string>): boolean;
/**
 * Can ANY key serve this model right now? The same gates hasOtherUsableKey
 * applies — scope (#657), per-key cooldown, and the provider/model rate and
 * token windows — with no key excluded. /v1/models uses it to tell a `ready`
 * model from an `exhausted` one (#1100), so the listing cannot claim a model
 * the router would immediately skip.
 */
export declare function hasUsableKeyForModel(modelDbId: number): boolean;
/**
 * Every key that can be ROUTED to this model: enabled + healthy/unknown, not
 * scoped away from the model (#657), and — for a custom model — belonging to
 * the model's own endpoint (#212, #619). Deliberately ignores the transient
 * gates hasOtherUsableKey applies (cooldown, quotas): the caller here is the
 * model-level bench, which needs the full key set to take a sick model out of
 * rotation, not "who could serve the next request".
 */
export declare function routableKeyIdsForModel(modelDbId: number): number[];
/**
 * Safety margin applied when ranking a model against an estimated request size.
 * The estimate is a chars/4 heuristic that under-counts dense payloads (JSON,
 * code, CJK) by up to ~2x; without any accounting for that gap such requests
 * were routed to models whose real tokenizer count exceeded the window and the
 * provider rejected them with a 400 mid-chain (kilo: "maximum context length is
 * 262144 tokens" on requests estimated <=256000).
 *
 * The margin is a SOFT preference, not a hard filter (#956 review): /v1/models
 * advertises the RAW window, so clients legitimately pack requests right up to
 * it. Excluding margin-violating models outright would turn an upstream 400
 * that the retry loop already classifies and handles (`context_too_large`)
 * into a regression: "all models exhausted" with zero attempts. Callers
 * therefore try margin-fitting candidates first and only fall back to raw
 * advertised-window fits (see fitsContextWindowStrict) when nothing else can
 * serve the request.
 */
export declare const CONTEXT_WINDOW_SAFETY_FACTOR = 1.25;
/** True when `estimatedTokens` fits the RAW advertised window (null window =
 * unknown, never filtered — same convention as the auto-router). This is the
 * comparison /v1/models publishes and the soft-preference fallback tier. */
export declare function fitsContextWindowStrict(contextWindow: number | null | undefined, estimatedTokens: number): boolean;
/** True when `estimatedTokens` plausibly fits `contextWindow` WITH the safety
 * margin. The chars/4 heuristic portion is scaled by the factor; an explicit
 * output reserve derived from the client's max_tokens (`routingReserveTokens`)
 * is already an exact count and is added UNSCALED (#956 review). Trim-guarded
 * platforms compare strictly — their guard guarantees the fit. */
export declare function fitsContextWindow(platform: string, contextWindow: number | null | undefined, estimatedTokens: number, exactOutputReserve?: number): boolean;
/**
 * Route to ONE specific model, hard-pinned. Rotates across that model's keys
 * (cooldowns, quotas, decryption all honored) but NEVER substitutes a different
 * model — returns null if the pinned model can't serve right now. This is what
 * makes a fusion panel genuinely diverse: a rate-limited slot is dropped, not
 * silently collapsed onto whatever else is available. `skipKeys` lets a slot
 * exclude keys it already failed on this request.
 */
export declare function routePinnedModel(modelDbId: number, estimatedTokens?: number, skipKeys?: Set<string>): RouteResult | null;
/**
 * Resolve a logical model group's member db ids to an ordered ChainRow[] for
 * strict group-pin routing (the "unify" feature). Each catalog-enabled member
 * is hydrated as a ChainRow carrying its active-profile/manual priority, then
 * ordered by the active strategy via orderChain. Auto-chain enabled/disabled is
 * intentionally ignored here because an explicit model request should still be
 * able to use a direct model that the user removed from auto routing.
 *
 * Pass the result to routeRequest() as `prefetchedChain` and DO NOT pass a
 * `preferredModelDbId` that isn't already one of these rows — otherwise the
 * preferred-model injection in routeRequest would unshift an off-group model and
 * the pin would no longer be strict (it could answer with a different model).
 */
export declare function resolveModelGroupCandidates(memberDbIds: number[], 
/**
 * Members that were reached only through a group's auto-derived slug, not the
 * id the client wrote (#651). They stay in the chain — resolution must never
 * shrink — but as a strictly lower tier, so they can serve only once every
 * literal match is exhausted. Omit it and every row is an equal candidate,
 * which is what every other caller wants.
 */
demotedDbIds?: ReadonlySet<number>): ChainRow[];
export interface FusionCandidate {
    modelDbId: number;
    platform: string;
    modelId: string;
    displayName: string;
    sizeLabel: string;
    supportsVision: number;
    supportsTools: number;
}
/**
 * The active fallback chain ordered by the current routing strategy, surfaced
 * for fusion panel selection. Same ordering the normal auto-router would walk,
 * so the panel's auto-pick draws from the highest-scored models first and the
 * fusion layer just needs to apply provider-diversity on top.
 */
export declare function getOrderedFusionChain(estimatedTokens: number, exactOutputReserve?: number): FusionCandidate[];
/**
 * Resolve an explicit model id (as a client would type it) to a fusion
 * candidate, or null when it isn't a known enabled model. Prefers an enabled
 * row; dedupes a model id that exists on multiple platforms by intelligence
 * rank, matching how /v1/models picks a representative row.
 */
export declare function resolveFusionCandidate(modelId: string): FusionCandidate | null;
export declare function routeRequest(estimatedTokens?: number, skipKeys?: Set<string>, preferredModelDbId?: number, requireVision?: boolean, requireTools?: boolean, skipModels?: Set<number>, prefetchedChain?: ChainRow[], requireStructured?: boolean, skipPlatforms?: Set<string>, exactOutputReserve?: number, task?: 'code' | 'chat', requireVideo?: boolean): RouteResult;
/**
 * Per-model routing scores for the dashboard. Deterministic (expected
 * reliability, not sampled) so the table is stable between polls. Returns the
 * axis breakdown plus the final score under the active strategy's weights.
 */
export interface RoutingScore {
    modelDbId: number;
    platform: string;
    modelId: string;
    displayName: string;
    enabled: boolean;
    reliability: number;
    speed: number;
    intelligence: number;
    headroom: number;
    rateLimit: number;
    score: number;
    totalRequests: number;
}
export declare function getRoutingScores(): {
    strategy: RoutingStrategy;
    keySelectionStrategy: KeySelectionStrategy;
    weights: RoutingWeights | null;
    customWeights: RoutingWeights;
    exploreEnabled: boolean;
    peakAdjusted: boolean;
    peakHours: PeakHoursConfig;
    scores: RoutingScore[];
};
/**
 * Filter a sticky-session pin down to something still routable (#634).
 *
 * A sticky entry holds a model db id for up to 30 minutes, so it goes stale the
 * moment the operator disables that model — in the catalog, or just for auto
 * routing. It must NOT be handed to routeRequest as-is: an off-chain preferred
 * id is treated as an explicit pin and injected ahead of the chain, which is
 * right for a client that named the model and wrong for a pin the client never
 * asked for. Dropping it here falls the request through to normal auto routing.
 *
 * Pass the same chain the request will route over (the prefetched auto chain);
 * omit it to check the active chain, which is what routeRequest would use.
 */
export declare function resolveStickyPreference(stickyModelDbId: number | undefined, chain?: ChainRow[]): number | undefined;
export declare function hasEnabledVisionModel(): boolean;
export declare function hasEnabledVideoModel(): boolean;
export declare function hasEnabledToolsModel(): boolean;
export {};
//# sourceMappingURL=router.d.ts.map