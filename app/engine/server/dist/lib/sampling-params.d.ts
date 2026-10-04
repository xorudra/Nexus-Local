import { z } from 'zod';
import type { Platform } from '@freellmapi/shared/types.js';
export declare const REASONING_EFFORTS: readonly ["none", "minimal", "low", "medium", "high"];
export type ReasoningEffort = typeof REASONING_EFFORTS[number];
/**
 * Coerce a client-supplied effort value onto our scale: supported values pass
 * through, known aliases clamp to the nearest supported one, and anything
 * else (unknown word, wrong type, "auto") yields undefined — the knob is
 * dropped and the provider's own default applies. Never throws, so a bad
 * effort can't fail a request. Exported for tests.
 */
export declare function normalizeReasoningEffort(value: unknown): ReasoningEffort | undefined;
export declare const samplingParamSchemaFields: {
    readonly top_k: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    readonly min_p: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    readonly seed: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    readonly presence_penalty: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    readonly frequency_penalty: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    readonly repetition_penalty: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    readonly logit_bias: z.ZodOptional<z.ZodNullable<z.ZodRecord<z.ZodString, z.ZodNumber>>>;
    readonly logprobs: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
    readonly top_logprobs: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    readonly response_format: z.ZodOptional<z.ZodNullable<z.ZodObject<{
        type: z.ZodEnum<["text", "json_object", "json_schema"]>;
        json_schema: z.ZodOptional<z.ZodObject<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        type: z.ZodEnum<["text", "json_object", "json_schema"]>;
        json_schema: z.ZodOptional<z.ZodObject<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        type: z.ZodEnum<["text", "json_object", "json_schema"]>;
        json_schema: z.ZodOptional<z.ZodObject<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
            name: z.ZodOptional<z.ZodString>;
            strict: z.ZodOptional<z.ZodNullable<z.ZodBoolean>>;
            schema: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
        }, z.ZodTypeAny, "passthrough">>>;
    }, z.ZodTypeAny, "passthrough">>>>;
    readonly reasoning_effort: z.ZodOptional<z.ZodUnknown>;
    readonly reasoning: z.ZodOptional<z.ZodNullable<z.ZodObject<{
        effort: z.ZodOptional<z.ZodUnknown>;
    }, "passthrough", z.ZodTypeAny, z.objectOutputType<{
        effort: z.ZodOptional<z.ZodUnknown>;
    }, z.ZodTypeAny, "passthrough">, z.objectInputType<{
        effort: z.ZodOptional<z.ZodUnknown>;
    }, z.ZodTypeAny, "passthrough">>>>;
    readonly max_completion_tokens: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
};
export interface ResponseFormat {
    type: 'json_object' | 'json_schema';
    json_schema?: {
        name?: string;
        strict?: boolean | null;
        schema?: Record<string, unknown>;
    } & Record<string, unknown>;
}
export interface ExtendedSamplingOptions {
    top_k?: number;
    min_p?: number;
    seed?: number;
    presence_penalty?: number;
    frequency_penalty?: number;
    repetition_penalty?: number;
    logit_bias?: Record<string, number>;
    logprobs?: boolean;
    top_logprobs?: number;
    response_format?: ResponseFormat;
    reasoning_effort?: ReasoningEffort;
}
export declare const EXTENDED_SAMPLING_KEYS: readonly ["top_k", "min_p", "seed", "presence_penalty", "frequency_penalty", "repetition_penalty", "logit_bias", "logprobs", "top_logprobs", "response_format", "reasoning_effort"];
export type ExtendedSamplingKey = typeof EXTENDED_SAMPLING_KEYS[number];
type ParsedSamplingBody = {
    [K in ExtendedSamplingKey]?: unknown;
} & {
    reasoning?: {
        effort?: unknown;
    } | null;
};
/**
 * Turn a schema-parsed request body into the extended CompletionOptions
 * fields: nulls dropped, `response_format: {type:'text'}` dropped (it is the
 * default and some providers 400 on receiving it explicitly), everything else
 * forwarded as-is.
 */
export declare function pickSamplingParams(body: ParsedSamplingBody): ExtendedSamplingOptions;
export interface PlatformParamPolicy {
    drop?: readonly ExtendedSamplingKey[];
    rename?: Readonly<Partial<Record<ExtendedSamplingKey, string>>>;
    jsonObjectToSchema?: boolean;
    jsonSchemaToObject?: boolean;
    reasoningEfforts?: readonly ReasoningEffort[];
    defaultMaxTokens?: number;
    maxTokensCap?: number;
}
/** GitHub Models' own output-token ceiling: asking for more 400s ("max_tokens
 *  is too large"), so the request never reaches the model. Wired into the
 *  github policy below as maxTokensCap. */
export declare const GITHUB_MAX_OUTPUT_TOKENS = 400;
export declare const PLATFORM_PARAM_POLICIES: Partial<Record<Platform, PlatformParamPolicy>>;
/**
 * Build the extended wire-body fields for one platform: policy droplist
 * applied, renames applied, undefined skipped. Adapters spread the result
 * into their OpenAI-shaped request bodies.
 */
export declare function extendedBodyParams(platform: string, options: ExtendedSamplingOptions | undefined): Record<string, unknown>;
/** The output-token floor this platform sends for a request that carries no
 *  max_tokens at all, or undefined when the provider's own default is fine. */
export declare function defaultMaxTokensFor(platform: string): number | undefined;
/** This platform's own output-token ceiling, or undefined when it accepts
 *  whatever max_tokens the client asks for. */
export declare function maxTokensCapFor(platform: string): number | undefined;
/**
 * The max_tokens to put on the wire for one request: whatever the client asked
 * for, or the platform's floor when the client asked for nothing (#553), then
 * lowered to the tightest ceiling that applies — the platform's own
 * maxTokensCap, the operator's unified cap, or both. With neither in play
 * nothing is clamped — a client-set value passes through untouched in both
 * directions, and the gateway's own guardrails (token budget, routing reserve)
 * have already had their say by the time an adapter calls this.
 *
 * EVERY adapter must send max_tokens through here, or the cap is not unified:
 * openai-compat (and its subclasses), cloudflare, cohere, google and aihorde
 * all do.
 */
export declare function resolveMaxTokens(platform: string, requested: number | undefined, contextBudget?: number): number | undefined;
export declare const UNIFIED_MAX_TOKENS_SETTING = "unified_max_tokens";
/** The ceiling 'auto' clamps to: the output limit of the largest common free
 *  catalog models. */
export declare const UNIFIED_MAX_TOKENS_AUTO = 32768;
/** The configured unified output cap, or null when disabled ('off'/unset).
 *  'auto' resolves to UNIFIED_MAX_TOKENS_AUTO; an explicit integer is used
 *  verbatim; anything else is treated as disabled so a bad value can't 400
 *  requests. Reads the settings table on every call — cheap (better-sqlite3
 *  sync read) and picks up dashboard changes without a restart, mirroring
 *  guardrails.ts. */
export declare function unifiedMaxTokensCap(): number | null;
/** True when this platform's policy strips response_format before send — the
 *  router uses it to skip such platforms for structured-output requests. */
export declare function platformDropsResponseFormat(platform: string): boolean;
/** The advertised parameter list for a model on `platform` — the base set
 *  every surface supports, plus tools when the model does, minus the
 *  platform's droplist. */
export declare function supportedParametersFor(platform: string, caps?: {
    tools?: boolean;
}): string[];
/** For a model served by several platforms (a unify group): the INTERSECTION
 *  of the members' supported sets — a param is only advertised when every
 *  platform the router might pick honors it. */
export declare function supportedParametersForPlatforms(platforms: string[], caps?: {
    tools?: boolean;
}): string[];
export {};
//# sourceMappingURL=sampling-params.d.ts.map