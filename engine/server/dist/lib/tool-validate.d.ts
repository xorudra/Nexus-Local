export declare const TOOL_ARGUMENT_VALIDATION_SETTING = "validate_tool_arguments";
export declare function isToolArgumentValidationEnabled(): boolean;
/**
 * Order-independent serialisation, so two schemas that differ only in key order
 * share one compiled validator.
 */
export declare function stableStringify(value: unknown): string;
export type ToolArgumentVerdict = {
    ok: true;
} | {
    ok: false;
    reason: string;
};
/**
 * Check `argsJson` against `schema`.
 *
 * Fails **open** in every case where we cannot form an opinion: no schema, a
 * schema Ajv will not compile, or arguments that are not JSON at all (the last
 * is someone else's error to report, and tool-args deliberately passes
 * unparseable arguments through untouched). Only a definite schema violation
 * returns a verdict, because the consequence of a verdict is a failover hop.
 */
export declare function validateToolArguments(toolName: string, argsJson: string, schema: unknown): ToolArgumentVerdict;
/**
 * The error thrown when a tool call cannot be served. The message carries the
 * marker `invalid tool arguments`, which `isRetryableError` recognises, so the
 * loop fails over exactly as it does for a dead dialect turn.
 *
 * `skipBench` because the PROVIDER is healthy — the model misbehaved, so no
 * cooldown or score penalty. `skipModelForRequest` because a sibling key would
 * misbehave identically, so the whole model is ruled out for this request.
 */
export declare function invalidToolArgumentsError(displayName: string, reasons: string[]): Error;
/**
 * Verdicts for a whole turn's tool calls. Returns the reasons for those that
 * violate their schema; an empty array means the turn is servable.
 */
export declare function invalidToolCallReasons(calls: Array<{
    function?: {
        name?: string;
        arguments?: string;
    };
}> | undefined, schemas: Map<string, unknown>): string[];
//# sourceMappingURL=tool-validate.d.ts.map