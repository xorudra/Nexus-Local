import { z } from 'zod';
export declare const CLAUDE_FAMILIES: readonly ["default", "opus", "sonnet", "haiku"];
export type ClaudeFamily = (typeof CLAUDE_FAMILIES)[number];
export type AnthropicModelMap = Record<ClaudeFamily, string>;
export declare const anthropicModelMapSchema: z.ZodObject<{
    default: z.ZodOptional<z.ZodString>;
    opus: z.ZodOptional<z.ZodString>;
    sonnet: z.ZodOptional<z.ZodString>;
    haiku: z.ZodOptional<z.ZodString>;
}, "strict", z.ZodTypeAny, {
    haiku?: string | undefined;
    default?: string | undefined;
    opus?: string | undefined;
    sonnet?: string | undefined;
}, {
    haiku?: string | undefined;
    default?: string | undefined;
    opus?: string | undefined;
    sonnet?: string | undefined;
}>;
export declare function getClaudeModelMap(): AnthropicModelMap;
export declare function setClaudeModelMap(input: unknown): AnthropicModelMap;
export declare function classifyClaudeFamily(model?: string): ClaudeFamily | null;
export interface ResolvedAnthropicModel {
    preferredModelDbId?: number;
    modelId?: string;
    pinned: boolean;
}
export declare function resolveAnthropicModel(model?: string): ResolvedAnthropicModel;
export declare const CLAUDE_FAMILY_ALIASES: {
    id: string;
    family: ClaudeFamily;
    label: string;
}[];
export declare function claudeFamilyDiscoveryEntries(): {
    id: string;
    displayName: string;
}[];
//# sourceMappingURL=anthropic-map.d.ts.map