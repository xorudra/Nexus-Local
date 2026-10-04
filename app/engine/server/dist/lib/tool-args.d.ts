interface JsonSchemaish {
    type?: string;
    properties?: Record<string, JsonSchemaish>;
    items?: JsonSchemaish;
}
/**
 * Repair a tool call's `arguments` JSON string against the tool's parameter
 * schema. Returns the original string untouched whenever anything doesn't
 * parse or doesn't match — this must never corrupt a valid call.
 */
export declare function repairToolArguments(args: string, paramSchema?: JsonSchemaish): string;
/**
 * Recursively remove the given keys from a JSON-Schema-ish value. Used to drop
 * fields a provider's tool-schema validator rejects with a 400 even though they
 * carry no meaning for the call — Cohere's compat endpoint, for instance, 400s
 * on `additionalProperties` (and `$schema`), which strict clients like opencode
 * and continue.dev routinely emit. Returns a NEW value; never mutates the input
 * (tools are shared across the fallback chain, so an in-place strip on one
 * provider would corrupt the schema the next provider sees). Non-object values
 * pass through unchanged. This is the provider-agnostic sibling of google.ts's
 * `sanitizeForGemini`, which strips a much larger Gemini-specific key set.
 */
export declare function stripSchemaKeys<T>(schema: T, keys: Set<string>): T;
/**
 * Build a tool-name → parameter-schema map from an OpenAI-style tools array
 * (chat-completions shape: {type:'function', function:{name, parameters}}).
 */
export declare function toolSchemaMap(tools?: Array<{
    type?: string;
    function?: {
        name?: string;
        parameters?: unknown;
    };
}>): Map<string, JsonSchemaish>;
export {};
//# sourceMappingURL=tool-args.d.ts.map