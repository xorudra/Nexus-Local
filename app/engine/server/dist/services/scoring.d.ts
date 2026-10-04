export interface RoutingWeights {
    reliability: number;
    speed: number;
    intelligence: number;
}
export type RoutingStrategy = 'priority' | 'balanced' | 'smartest' | 'fastest' | 'reliable' | 'efficient' | 'auto' | 'custom';
export type KeySelectionStrategy = 'auto' | 'least-remaining';
export declare const BANDIT_PRESETS: Record<Exclude<RoutingStrategy, 'priority' | 'custom'>, RoutingWeights>;
export declare const DEFAULT_STRATEGY: RoutingStrategy;
export declare function efficiencyFactor(sizeLabel: string | null | undefined): number;
/** Persisted peak-hours settings. `enabled` false ⇒ presets are untouched. */
export interface PeakHoursConfig {
    enabled: boolean;
    /** Window start hour, inclusive, 0–23. */
    startHour: number;
    /** Window end hour, exclusive, 0–23. May be < startHour (window spans midnight). */
    endHour: number;
    /** IANA timezone name the hours are interpreted in. */
    timezone: string;
}
export declare const DEFAULT_PEAK_START_HOUR = 18;
export declare const DEFAULT_PEAK_END_HOUR = 6;
export declare const DEFAULT_PEAK_TIMEZONE = "UTC";
/** Fraction of the speed weight moved onto reliability during peak hours. */
export declare const PEAK_SPEED_TO_RELIABILITY = 0.6;
export declare const DEFAULT_PEAK_HOURS: PeakHoursConfig;
/**
 * Presets exempt from the peak adjustment.
 *
 * `fastest` and `reliable` are the two ends of the speed↔reliability axis, and
 * they are what an operator picks when they have already decided which end they
 * want. Shifting 60% of `fastest`'s 0.55 speed weight would leave it at
 * reliability 0.68 / speed 0.22 — i.e. `fastest` would quietly become a slightly
 * noisy copy of `reliable`, which is a different preset the user could have
 * selected. `reliable` is exempt for the mirror-image reason: it is already the
 * reliability extreme, so there is nothing the adjustment can add, and moving
 * its speed weight only pushes it past the range any preset offers. The
 * adjustment therefore applies only to the mixed presets (`balanced`,
 * `smartest`), where trading some speed weight for reliability stays inside the
 * span the presets already describe. Clamping instead of exempting was the
 * alternative; exempting is chosen because it keeps each preset's identity
 * exactly, rather than making two of them silently converge on a third.
 */
export declare const PEAK_EXEMPT_STRATEGIES: readonly RoutingStrategy[];
/** Whether this strategy opts out of the peak adjustment (see above). */
export declare function isPeakExemptStrategy(strategy: RoutingStrategy): boolean;
/** True when `hour` is a whole number in 0–23. */
export declare function isValidPeakHour(hour: unknown): hour is number;
/** True when `timezone` is an IANA name this runtime's ICU data knows. */
export declare function isValidTimezone(timezone: unknown): timezone is string;
/**
 * The hour (0–23) at `now` in `timezone`. Uses Intl rather than Date#getHours
 * so the window means the same thing regardless of the host's TZ. An unknown
 * timezone falls back to UTC instead of throwing — routing must never fail
 * because a settings row went stale.
 */
export declare function hourInTimezone(now: Date, timezone: string): number;
/**
 * True when `now` falls inside the configured window. `startHour === endHour`
 * is an EMPTY window, not a 24-hour one: an operator who drags both ends to the
 * same value means "nothing", and the alternative (always peak) would be a
 * permanent silent reweight from a config that looks like a no-op.
 */
export declare function isPeakHours(config: PeakHoursConfig, now?: Date): boolean;
/**
 * Peak-adjusted weights for a bandit preset, plus whether the adjustment
 * actually fired (the dashboard labels the weight summary from that flag).
 * Returns the base vector untouched when the feature is off, when the clock is
 * outside the window, or when the strategy is exempt.
 */
export declare function peakAdjustedWeights(base: RoutingWeights, strategy: RoutingStrategy, config: PeakHoursConfig, now?: Date): {
    weights: RoutingWeights;
    adjusted: boolean;
};
export declare const TASK_WEIGHT_SHARE = 0.3;
/**
 * Presets exempt from the task-type bias.
 *
 * The same reasoning as `PEAK_EXEMPT_STRATEGIES` (see above), plus `custom`:
 * `fastest` and `reliable` are the ends of the axis an operator picks when they
 * have already decided which end they want, and rewriting them turns one preset
 * into a noisy copy of another; `custom` is the operator's hand-set sliders, the
 * one weight vector they typed themselves, so a per-request header must not move
 * it. The bias therefore applies only to the mixed presets (`balanced`,
 * `smartest`). `priority` never reaches here — it has no weight vector at all.
 */
export declare const TASK_EXEMPT_STRATEGIES: readonly RoutingStrategy[];
/** Whether this strategy opts out of the task-type bias (see above). */
export declare function isTaskExemptStrategy(strategy: RoutingStrategy): boolean;
export declare function taskAdjustedWeights(base: RoutingWeights, task: 'code' | 'chat', strategy: RoutingStrategy, share?: number): {
    weights: RoutingWeights;
    adjusted: boolean;
};
export declare const PRIOR_SUCCESS = 1;
export declare const PRIOR_FAILURE = 1;
/** Community-sourced prior counts, folded into the Beta posterior as the
 *  starting balance (#685 follow-up). `successes`/`failures` are the
 *  decay-weighted LOCAL sample counts; the community numbers are the
 *  aggregated, de-poisoned counts from other instances. Local samples dilute
 *  the community prior automatically: the more this install has observed, the
 *  less the shared starting point matters. */
export interface CommunityReliabilityPrior {
    successes: number;
    failures: number;
}
export declare function reliabilityPosterior(successes: number, failures: number, community?: CommunityReliabilityPrior): {
    alpha: number;
    beta: number;
};
export declare function expectedReliability(successes: number, failures: number, community?: CommunityReliabilityPrior): number;
export declare const SPEED_SCALE_TOK_S = 60;
export declare const TTFB_BEST_MS = 300;
export declare const TTFB_WORST_MS = 5000;
export declare const SPEED_PRIOR = 0.6;
/**
 * Blend throughput and TTFB into a single [0,1] speed score.
 * `tokPerSec <= 0` means no successful samples → return the exploration prior.
 * `ttfbMs === null` means we have throughput but no first-byte timing → fall
 * back to throughput alone rather than guessing latency.
 */
export declare function speedScore(tokPerSec: number, ttfbMs: number | null): number;
export declare const TIMEOUT_LATENCY_CAP_MS = 120000;
export declare const OBSERVED_SPEED_RANK_BEST = 1;
export declare const OBSERVED_SPEED_RANK_WORST = 10;
export declare function observedSpeedRank(speed: number): number;
export declare const TIER_VALUE: Record<string, number>;
export declare function tierValue(sizeLabel: string): number;
export declare function intelligenceComposite(sizeLabel: string, intelligenceRank: number): number;
export declare function intelligenceScore(composite: number, min: number, max: number): number;
export declare const HEADROOM_FLOOR = 0.1;
export declare const HEADROOM_RAMP_START = 0.2;
export interface HeadroomThresholds {
    /** Remaining-budget fraction at which demotion begins (0..1). */
    rampStart?: number;
    /** Score floor while a model is at 0 remaining budget (0..1). */
    floor?: number;
}
export declare function headroomFactor(usedTokens: number, budgetTokens: number, opts?: HeadroomThresholds): number;
export declare function rateWindowHeadroomFactor(usedFraction: number | null, opts?: HeadroomThresholds): number;
export declare const MAX_PENALTY = 10;
export declare const RATE_LIMIT_MAX_DAMP = 0.6;
export declare function rateLimitFactor(penalty: number): number;
export declare function sampleBeta(alpha: number, beta: number): number;
export interface ScoreInputs {
    reliability: number;
    speed: number;
    intelligence: number;
    headroom: number;
    rateLimit: number;
}
/**
 * Convex base (∈[0,1]) × the two guardrail multipliers. The weights are assumed
 * to sum to 1; if a caller passes a non-normalized vector we renormalize so the
 * base never escapes [0,1].
 */
export declare function combineScore(inputs: ScoreInputs, weights: RoutingWeights): number;
//# sourceMappingURL=scoring.d.ts.map