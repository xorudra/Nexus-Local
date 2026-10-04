import { z } from 'zod';
import { type CompressionConfig, type CompressionMode } from './types.js';
export declare const COMPRESSION_SETTING = "compression";
export declare const DEFAULT_COMPRESSION_CONFIG: CompressionConfig;
export declare const compressionUpdateSchema: z.ZodObject<{
    mode: z.ZodOptional<z.ZodEnum<["off", "lossless", "standard", "aggressive"]>>;
    engines: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodRecord<z.ZodString, z.ZodUnknown>>>;
    autoTriggerEstTokens: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    targetTokens: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    trustProjectFilters: z.ZodOptional<z.ZodBoolean>;
    prefixFreeze: z.ZodOptional<z.ZodBoolean>;
}, "strict", z.ZodTypeAny, {
    mode?: "standard" | "off" | "lossless" | "aggressive" | undefined;
    trustProjectFilters?: boolean | undefined;
    targetTokens?: number | null | undefined;
    engines?: Record<string, Record<string, unknown>> | undefined;
    autoTriggerEstTokens?: number | null | undefined;
    prefixFreeze?: boolean | undefined;
}, {
    mode?: "standard" | "off" | "lossless" | "aggressive" | undefined;
    trustProjectFilters?: boolean | undefined;
    targetTokens?: number | null | undefined;
    engines?: Record<string, Record<string, unknown>> | undefined;
    autoTriggerEstTokens?: number | null | undefined;
    prefixFreeze?: boolean | undefined;
}>;
export declare function getCompressionConfig(): CompressionConfig;
export declare function setCompressionConfig(update: z.infer<typeof compressionUpdateSchema>): CompressionConfig;
export type CompressionDirective = 'default' | 'off' | 'on' | Exclude<CompressionMode, 'off'>;
export declare function parseCompressionDirective(header: string | string[] | undefined): CompressionDirective;
export declare function resolveCompressionMode(config: CompressionConfig, directive: CompressionDirective): CompressionMode;
export declare function compressionConfigFingerprint(config: CompressionConfig, mode: CompressionMode): string;
//# sourceMappingURL=config.d.ts.map