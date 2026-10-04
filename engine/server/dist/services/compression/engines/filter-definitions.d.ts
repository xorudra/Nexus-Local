import { z } from 'zod';
export declare const filterRuleSchema: z.ZodObject<{
    id: z.ZodString;
    version: z.ZodDefault<z.ZodNumber>;
    detect: z.ZodObject<{
        toolNames: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
        content: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        content: string[];
        toolNames: string[];
    }, {
        content?: string[] | undefined;
        toolNames?: string[] | undefined;
    }>;
    stripAnsi: z.ZodDefault<z.ZodBoolean>;
    dropLines: z.ZodDefault<z.ZodArray<z.ZodObject<{
        pattern: z.ZodString;
        unless: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        pattern: string;
        unless?: string | undefined;
    }, {
        pattern: string;
        unless?: string | undefined;
    }>, "many">>;
    keepLines: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
    collapseRuns: z.ZodOptional<z.ZodObject<{
        min: z.ZodDefault<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        min: number;
    }, {
        min?: number | undefined;
    }>>;
    headTail: z.ZodDefault<z.ZodBoolean>;
    maxChars: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    id: string;
    version: number;
    detect: {
        content: string[];
        toolNames: string[];
    };
    stripAnsi: boolean;
    dropLines: {
        pattern: string;
        unless?: string | undefined;
    }[];
    keepLines: string[];
    headTail: boolean;
    collapseRuns?: {
        min: number;
    } | undefined;
    maxChars?: number | undefined;
}, {
    id: string;
    detect: {
        content?: string[] | undefined;
        toolNames?: string[] | undefined;
    };
    version?: number | undefined;
    stripAnsi?: boolean | undefined;
    dropLines?: {
        pattern: string;
        unless?: string | undefined;
    }[] | undefined;
    keepLines?: string[] | undefined;
    collapseRuns?: {
        min?: number | undefined;
    } | undefined;
    headTail?: boolean | undefined;
    maxChars?: number | undefined;
}>;
export type ToolFilterRule = z.infer<typeof filterRuleSchema>;
export declare const BUILTIN_FILTERS: ToolFilterRule[];
//# sourceMappingURL=filter-definitions.d.ts.map