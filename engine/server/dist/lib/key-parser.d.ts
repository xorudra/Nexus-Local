/** One model id from a `*_MODELS` list (#382). A capability flag is set only
 *  when the paste declared it via a trailing `-TOOLS` / `-VISION` suffix;
 *  unset means "no opinion" so registration keeps its own defaults. */
export interface ParsedModelEntry {
    id: string;
    supportsTools?: boolean;
    supportsVision?: boolean;
}
export interface ParsedKey {
    rawKey: string;
    prefix: string;
    platform: string | null;
    /** Custom OpenAI-compatible endpoints are identified by their base_url, so a
     *  'custom' key is meaningless without one — the importer refuses those. Set
     *  by the formats that can carry it (export JSON, CSV, and the paired
     *  CUSTOM_<n>_BASE_URL / CUSTOM_<n>_KEY convention in .env). */
    baseUrl?: string;
    /** Custom endpoints only: models declared beside the key via
     *  CUSTOM_<n>_MODELS / <PREFIX>_CUSTOM_MODELS (#382). */
    models?: ParsedModelEntry[];
    /** Display name carried by a format that has one (CSV column 3, export
     *  JSON `label`). The import route stores it when present instead of
     *  falling back to the generated env-var-style name — without it a CSV
     *  round trip renamed every key. */
    label?: string;
}
/** A key/value pair on its way to becoming a ParsedKey. `platform` and
 *  `baseUrl` are set only by formats that state them outright (CSV names the
 *  platform in a column); otherwise the platform is inferred from the prefix. */
interface KeyPair {
    key: string;
    value: string;
    platform?: string;
    baseUrl?: string;
    label?: string;
    models?: ParsedModelEntry[];
}
export interface ParseResult {
    keys: ParsedKey[];
    skipped: string[];
}
export declare const PREFIX_MAP: Record<string, string>;
export declare const AUTH_JSON_PROVIDER_MAP: Record<string, string>;
export declare function detectPlatform(prefix: string): string | null;
export declare function parseDotEnv(content: string): Array<{
    key: string;
    value: string;
}>;
export declare function stripJsoncComments(text: string): string;
export declare function stripTrailingCommas(text: string): string;
export declare function parseJson(content: string): Array<{
    key: string;
    value: string;
}>;
/**
 * Parse the FreeLLMAPI export JSON format:
 * { version: 1, exportedAt, source, keys: [{ platform, key, label, baseUrl? }] }
 * Returns key-value pairs compatible with toParsedKeys().
 */
export declare function parseExportJson(content: string): ParseResult | null;
/**
 * Parse CSV format: platform,key,label[,base_url] (with optional header row).
 * The trailing base_url column is what makes a 'custom' row importable — an
 * endpoint is identified by its URL, so a custom key without one is orphaned.
 */
export declare function parseCsv(content: string): KeyPair[];
export declare function parseAuthJson(content: string): ParseResult;
/**
 * Parse a comma-separated model list (#382). Trailing `-TOOLS` / `-VISION`
 * suffixes — either order, possibly both — strip off the stored id and set the
 * matching capability flag. Trailing ONLY: a TOOLS/VISION inside the id is
 * part of the id, and the suffixes are uppercase by convention so a real model
 * id ending in `-tools` is never mangled.
 */
export declare function parseModelList(value: string): ParsedModelEntry[];
export declare function looksLikeApiKey(value: string): boolean;
export declare function parseKeysFromFile(content: string, filename: string): ParseResult;
export {};
//# sourceMappingURL=key-parser.d.ts.map