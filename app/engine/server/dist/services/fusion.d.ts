import { z } from 'zod';
import type { ChatMessage, ChatCompletionChoice, ChatCompletionResponse, ChatToolCall, TokenUsage } from '@freellmapi/shared/types.js';
import { type FusionCandidate } from './router.js';
import type { CompletionOptions } from '../providers/base.js';
export declare const FUSION_MODEL_ID = "fusion";
export declare function isFusionModel(modelId: string | undefined): boolean;
export declare const fusionConfigSchema: z.ZodObject<{
    models: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    k: z.ZodOptional<z.ZodNumber>;
    judge: z.ZodOptional<z.ZodString>;
    strategy: z.ZodOptional<z.ZodEnum<["synthesize", "best_of"]>>;
    expose_panel: z.ZodOptional<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    models?: string[] | undefined;
    k?: number | undefined;
    judge?: string | undefined;
    strategy?: "synthesize" | "best_of" | undefined;
    expose_panel?: boolean | undefined;
}, {
    models?: string[] | undefined;
    k?: number | undefined;
    judge?: string | undefined;
    strategy?: "synthesize" | "best_of" | undefined;
    expose_panel?: boolean | undefined;
}>;
export type FusionConfig = z.infer<typeof fusionConfigSchema>;
export declare function getFusionMaxK(): number;
export declare const savedFusionConfigSchema: z.ZodObject<{
    mode: z.ZodEnum<["auto", "explicit"]>;
    models: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
    judge: z.ZodDefault<z.ZodNullable<z.ZodString>>;
    k: z.ZodNumber;
    strategy: z.ZodEnum<["synthesize", "best_of"]>;
    expose_panel: z.ZodBoolean;
}, "strip", z.ZodTypeAny, {
    mode: "auto" | "explicit";
    models: string[];
    k: number;
    judge: string | null;
    strategy: "synthesize" | "best_of";
    expose_panel: boolean;
}, {
    mode: "auto" | "explicit";
    k: number;
    strategy: "synthesize" | "best_of";
    expose_panel: boolean;
    models?: string[] | undefined;
    judge?: string | null | undefined;
}>;
export type SavedFusionConfig = z.infer<typeof savedFusionConfigSchema>;
export declare function getSavedFusionConfig(): SavedFusionConfig;
export declare function setSavedFusionConfig(input: SavedFusionConfig): SavedFusionConfig;
export declare function pruneUnavailableSavedFusionConfig(): SavedFusionConfig;
/**
 * Merge a request's inline fusion config over the saved dashboard default.
 * Each field present on the request wins; otherwise the saved default applies.
 * An explicit panel only comes from the saved config when its mode is
 * 'explicit' — in 'auto' mode the saved `models` are ignored so the panel is
 * picked fresh off the Fallback Chain.
 */
export declare function resolveEffectiveConfig(req: FusionConfig): FusionConfig;
interface PanelAnswer {
    modelDbId: number;
    platform: string;
    modelId: string;
    displayName: string;
    status: 'ok' | 'failed';
    content?: string;
    toolCalls?: ChatToolCall[];
    rawChoice?: ChatCompletionChoice;
    error?: string;
    usage?: TokenUsage;
}
/**
 * Collapse a provider-specific model id to its rough model FAMILY: drop the
 * provider prefix (everything up to the last '/') and any ':tag'/':free' suffix,
 * so e.g. `qwen/qwen3-coder:free` and `qwen3-coder:480b` map to one family.
 * Deliberately a SIMPLE heuristic, not a maintained alias map — cross-provider
 * id naming drifts constantly, so we only want a good-enough signal to avoid
 * stacking the panel with the same model served under two providers.
 */
export declare function familyKey(modelId: string): string;
/**
 * Order a strategy-sorted servable chain for panel diversity along TWO axes:
 * provider (platform) AND model family. Fusion's value comes from genuinely
 * DIFFERENT perspectives (issue #326 spike: a panel only beats the best single
 * model when its members actually disagree); the same model family served by
 * two providers is platform-distinct but perspective-redundant — one viewpoint
 * filling two slots.
 *
 * Two stable passes, each preserving the routing-strategy order it's handed:
 *  1. Provider-first (the existing invariant): one model per distinct platform
 *     before doubling up, so the panel spans different backends / failure
 *     domains.
 *  2. Family-dedup: within that provider-diverse order, demote any model whose
 *     family already appeared — a fresh family takes the slot first, and the
 *     redundant copy sinks to the refill tail rather than being dropped.
 * Pure function of its input (unit-tested directly).
 */
export declare function diversifyChain(ordered: FusionCandidate[]): FusionCandidate[];
/**
 * Build the panel plus a refill queue:
 *  - `panel`    — the K models to run first (explicit list, or provider-diverse
 *                 picks off the strategy-sorted chain).
 *  - `overflow` — the next servable models from the chain, used to refill a slot
 *                 when a panel model fails outright (auto mode only; an explicit
 *                 panel is run as-is with no substitution).
 * Diversity = distinct provider AND model family first (see diversifyChain), so
 * both the panel and its refills span genuinely different perspectives before
 * doubling up on either axis.
 */
export declare function selectPanel(config: FusionConfig, requirements: {
    requireTools?: boolean;
    requireVision?: boolean;
    estimatedTokens: number;
}): {
    panel: FusionCandidate[];
    overflow: FusionCandidate[];
    dropped: string[];
};
export declare function buildJudgeMessages(original: ChatMessage[], answers: PanelAnswer[], stripImages?: boolean): ChatMessage[];
export interface FusionResult {
    response: ChatCompletionResponse & {
        x_fusion?: unknown;
    };
    routedVia: string;
}
/**
 * Orchestrate a fusion request end to end: select the panel, fan out in
 * parallel, then synthesize survivors with a judge (or best-of). Throws a
 * FusionError when nothing usable comes back so the route can map it to an
 * HTTP status.
 */
export declare class FusionError extends Error {
    status: number;
    constructor(message: string, status: number);
}
export interface FusionHooks {
    onPanel?: (a: {
        platform: string;
        model: string;
        status: 'ok' | 'failed';
        content?: string;
        tool_calls?: ChatToolCall[];
        error?: string;
    }) => void;
    onJudge?: (j: {
        platform: string;
        model: string;
    }) => void;
    onJudgeDelta?: (text: string) => void;
}
export declare function runFusion(params: {
    messages: ChatMessage[];
    config: FusionConfig;
    options: CompletionOptions;
    estimatedTokens: number;
    hooks?: FusionHooks;
    vision?: boolean;
}): Promise<FusionResult>;
export {};
//# sourceMappingURL=fusion.d.ts.map