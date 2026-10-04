import { z } from 'zod';
declare const declarativeConfigSchema: z.ZodObject<{
    admin: z.ZodOptional<z.ZodObject<{
        email: z.ZodString;
        password: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        password: string;
        email: string;
    }, {
        password: string;
        email: string;
    }>>;
    license: z.ZodOptional<z.ZodString>;
    keys: z.ZodOptional<z.ZodArray<z.ZodObject<{
        platform: z.ZodString;
        key: z.ZodOptional<z.ZodString>;
        label: z.ZodOptional<z.ZodString>;
        baseUrl: z.ZodOptional<z.ZodString>;
        enabled: z.ZodOptional<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        platform: string;
        enabled?: boolean | undefined;
        key?: string | undefined;
        label?: string | undefined;
        baseUrl?: string | undefined;
    }, {
        platform: string;
        enabled?: boolean | undefined;
        key?: string | undefined;
        label?: string | undefined;
        baseUrl?: string | undefined;
    }>, "many">>;
    customProviders: z.ZodOptional<z.ZodArray<z.ZodObject<{
        baseUrl: z.ZodString;
        apiKey: z.ZodOptional<z.ZodString>;
        label: z.ZodOptional<z.ZodString>;
        models: z.ZodDefault<z.ZodArray<z.ZodUnion<[z.ZodString, z.ZodObject<{
            model: z.ZodString;
            displayName: z.ZodOptional<z.ZodString>;
            intelligenceRank: z.ZodOptional<z.ZodNumber>;
            speedRank: z.ZodOptional<z.ZodNumber>;
            sizeLabel: z.ZodOptional<z.ZodString>;
            monthlyTokenBudget: z.ZodOptional<z.ZodString>;
            contextWindow: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
            supportsVision: z.ZodOptional<z.ZodBoolean>;
            supportsTools: z.ZodOptional<z.ZodBoolean>;
            fallbackEnabled: z.ZodOptional<z.ZodBoolean>;
        }, "strip", z.ZodTypeAny, {
            model: string;
            displayName?: string | undefined;
            intelligenceRank?: number | undefined;
            speedRank?: number | undefined;
            sizeLabel?: string | undefined;
            monthlyTokenBudget?: string | undefined;
            contextWindow?: number | null | undefined;
            supportsVision?: boolean | undefined;
            supportsTools?: boolean | undefined;
            fallbackEnabled?: boolean | undefined;
        }, {
            model: string;
            displayName?: string | undefined;
            intelligenceRank?: number | undefined;
            speedRank?: number | undefined;
            sizeLabel?: string | undefined;
            monthlyTokenBudget?: string | undefined;
            contextWindow?: number | null | undefined;
            supportsVision?: boolean | undefined;
            supportsTools?: boolean | undefined;
            fallbackEnabled?: boolean | undefined;
        }>]>, "many">>;
    }, "strip", z.ZodTypeAny, {
        models: (string | {
            model: string;
            displayName?: string | undefined;
            intelligenceRank?: number | undefined;
            speedRank?: number | undefined;
            sizeLabel?: string | undefined;
            monthlyTokenBudget?: string | undefined;
            contextWindow?: number | null | undefined;
            supportsVision?: boolean | undefined;
            supportsTools?: boolean | undefined;
            fallbackEnabled?: boolean | undefined;
        })[];
        baseUrl: string;
        label?: string | undefined;
        apiKey?: string | undefined;
    }, {
        baseUrl: string;
        models?: (string | {
            model: string;
            displayName?: string | undefined;
            intelligenceRank?: number | undefined;
            speedRank?: number | undefined;
            sizeLabel?: string | undefined;
            monthlyTokenBudget?: string | undefined;
            contextWindow?: number | null | undefined;
            supportsVision?: boolean | undefined;
            supportsTools?: boolean | undefined;
            fallbackEnabled?: boolean | undefined;
        })[] | undefined;
        label?: string | undefined;
        apiKey?: string | undefined;
    }>, "many">>;
    models: z.ZodOptional<z.ZodArray<z.ZodObject<{
        platform: z.ZodString;
        modelId: z.ZodString;
        endpoint: z.ZodOptional<z.ZodString>;
        displayName: z.ZodOptional<z.ZodString>;
        intelligenceRank: z.ZodOptional<z.ZodNumber>;
        speedRank: z.ZodOptional<z.ZodNumber>;
        sizeLabel: z.ZodOptional<z.ZodString>;
        rpmLimit: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
        rpdLimit: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
        tpmLimit: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
        tpdLimit: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
        monthlyTokenBudget: z.ZodOptional<z.ZodString>;
        contextWindow: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
        enabled: z.ZodOptional<z.ZodBoolean>;
        supportsVision: z.ZodOptional<z.ZodBoolean>;
        supportsTools: z.ZodOptional<z.ZodBoolean>;
        fallbackEnabled: z.ZodOptional<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        displayName?: string | undefined;
        intelligenceRank?: number | undefined;
        speedRank?: number | undefined;
        sizeLabel?: string | undefined;
        rpmLimit?: number | null | undefined;
        rpdLimit?: number | null | undefined;
        tpmLimit?: number | null | undefined;
        tpdLimit?: number | null | undefined;
        monthlyTokenBudget?: string | undefined;
        contextWindow?: number | null | undefined;
        supportsVision?: boolean | undefined;
        supportsTools?: boolean | undefined;
        fallbackEnabled?: boolean | undefined;
    }, {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        displayName?: string | undefined;
        intelligenceRank?: number | undefined;
        speedRank?: number | undefined;
        sizeLabel?: string | undefined;
        rpmLimit?: number | null | undefined;
        rpdLimit?: number | null | undefined;
        tpmLimit?: number | null | undefined;
        tpdLimit?: number | null | undefined;
        monthlyTokenBudget?: string | undefined;
        contextWindow?: number | null | undefined;
        supportsVision?: boolean | undefined;
        supportsTools?: boolean | undefined;
        fallbackEnabled?: boolean | undefined;
    }>, "many">>;
    fallback: z.ZodOptional<z.ZodArray<z.ZodObject<{
        platform: z.ZodString;
        modelId: z.ZodString;
        endpoint: z.ZodOptional<z.ZodString>;
        priority: z.ZodOptional<z.ZodNumber>;
        enabled: z.ZodOptional<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        priority?: number | undefined;
    }, {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        priority?: number | undefined;
    }>, "many">>;
    routing: z.ZodOptional<z.ZodObject<{
        strategy: z.ZodEnum<["priority", "balanced", "smartest", "fastest", "reliable", "efficient", "auto", "custom"]>;
        weights: z.ZodOptional<z.ZodObject<{
            reliability: z.ZodNumber;
            speed: z.ZodNumber;
            intelligence: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            reliability: number;
            speed: number;
            intelligence: number;
        }, {
            reliability: number;
            speed: number;
            intelligence: number;
        }>>;
        keySelectionStrategy: z.ZodOptional<z.ZodEnum<["auto", "least-remaining"]>>;
    }, "strip", z.ZodTypeAny, {
        strategy: "custom" | "auto" | "balanced" | "priority" | "smartest" | "fastest" | "reliable" | "efficient";
        weights?: {
            reliability: number;
            speed: number;
            intelligence: number;
        } | undefined;
        keySelectionStrategy?: "auto" | "least-remaining" | undefined;
    }, {
        strategy: "custom" | "auto" | "balanced" | "priority" | "smartest" | "fastest" | "reliable" | "efficient";
        weights?: {
            reliability: number;
            speed: number;
            intelligence: number;
        } | undefined;
        keySelectionStrategy?: "auto" | "least-remaining" | undefined;
    }>>;
}, "strict", z.ZodTypeAny, {
    keys?: {
        platform: string;
        enabled?: boolean | undefined;
        key?: string | undefined;
        label?: string | undefined;
        baseUrl?: string | undefined;
    }[] | undefined;
    models?: {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        displayName?: string | undefined;
        intelligenceRank?: number | undefined;
        speedRank?: number | undefined;
        sizeLabel?: string | undefined;
        rpmLimit?: number | null | undefined;
        rpdLimit?: number | null | undefined;
        tpmLimit?: number | null | undefined;
        tpdLimit?: number | null | undefined;
        monthlyTokenBudget?: string | undefined;
        contextWindow?: number | null | undefined;
        supportsVision?: boolean | undefined;
        supportsTools?: boolean | undefined;
        fallbackEnabled?: boolean | undefined;
    }[] | undefined;
    fallback?: {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        priority?: number | undefined;
    }[] | undefined;
    admin?: {
        password: string;
        email: string;
    } | undefined;
    license?: string | undefined;
    customProviders?: {
        models: (string | {
            model: string;
            displayName?: string | undefined;
            intelligenceRank?: number | undefined;
            speedRank?: number | undefined;
            sizeLabel?: string | undefined;
            monthlyTokenBudget?: string | undefined;
            contextWindow?: number | null | undefined;
            supportsVision?: boolean | undefined;
            supportsTools?: boolean | undefined;
            fallbackEnabled?: boolean | undefined;
        })[];
        baseUrl: string;
        label?: string | undefined;
        apiKey?: string | undefined;
    }[] | undefined;
    routing?: {
        strategy: "custom" | "auto" | "balanced" | "priority" | "smartest" | "fastest" | "reliable" | "efficient";
        weights?: {
            reliability: number;
            speed: number;
            intelligence: number;
        } | undefined;
        keySelectionStrategy?: "auto" | "least-remaining" | undefined;
    } | undefined;
}, {
    keys?: {
        platform: string;
        enabled?: boolean | undefined;
        key?: string | undefined;
        label?: string | undefined;
        baseUrl?: string | undefined;
    }[] | undefined;
    models?: {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        displayName?: string | undefined;
        intelligenceRank?: number | undefined;
        speedRank?: number | undefined;
        sizeLabel?: string | undefined;
        rpmLimit?: number | null | undefined;
        rpdLimit?: number | null | undefined;
        tpmLimit?: number | null | undefined;
        tpdLimit?: number | null | undefined;
        monthlyTokenBudget?: string | undefined;
        contextWindow?: number | null | undefined;
        supportsVision?: boolean | undefined;
        supportsTools?: boolean | undefined;
        fallbackEnabled?: boolean | undefined;
    }[] | undefined;
    fallback?: {
        platform: string;
        modelId: string;
        enabled?: boolean | undefined;
        endpoint?: string | undefined;
        priority?: number | undefined;
    }[] | undefined;
    admin?: {
        password: string;
        email: string;
    } | undefined;
    license?: string | undefined;
    customProviders?: {
        baseUrl: string;
        models?: (string | {
            model: string;
            displayName?: string | undefined;
            intelligenceRank?: number | undefined;
            speedRank?: number | undefined;
            sizeLabel?: string | undefined;
            monthlyTokenBudget?: string | undefined;
            contextWindow?: number | null | undefined;
            supportsVision?: boolean | undefined;
            supportsTools?: boolean | undefined;
            fallbackEnabled?: boolean | undefined;
        })[] | undefined;
        label?: string | undefined;
        apiKey?: string | undefined;
    }[] | undefined;
    routing?: {
        strategy: "custom" | "auto" | "balanced" | "priority" | "smartest" | "fastest" | "reliable" | "efficient";
        weights?: {
            reliability: number;
            speed: number;
            intelligence: number;
        } | undefined;
        keySelectionStrategy?: "auto" | "least-remaining" | undefined;
    } | undefined;
}>;
export type DeclarativeConfig = z.infer<typeof declarativeConfigSchema>;
export interface DeclarativeConfigResult {
    applied: boolean;
    source?: string;
    /** True when the `admin` entry created the first dashboard account. */
    admin: boolean;
    /** True when a `license` entry was handed to background activation. */
    license: boolean;
    keys: number;
    customModels: number;
    models: number;
    fallback: number;
    routing: boolean;
    /** Per-entry problems that were degraded to a skip instead of failing the apply (#600). */
    warnings: string[];
}
export declare function applyDeclarativeConfig(input: unknown, source?: string): DeclarativeConfigResult;
/**
 * Activate a Premium license key from declarative config. Idempotent across
 * boots: a stored key identical to the configured one short-circuits before
 * any network call, while a different key re-activates (rotation). Exported
 * for tests.
 */
export declare function activateConfiguredLicense(key: string): Promise<void>;
export declare function applyDeclarativeConfigFromEnv(): DeclarativeConfigResult;
export {};
//# sourceMappingURL=declarative-config.d.ts.map