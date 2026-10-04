/**
 * Coerce an arbitrary string into a valid HTTP header field value. Never
 * throws, and never returns a value Node will reject.
 */
export declare function safeHeaderValue(value: string, maxLength?: number): string;
/** `<platform>/<model>` for X-Routed-Via, sanitized. */
export declare function routedViaValue(platform: string, modelId: string): string;
//# sourceMappingURL=header-value.d.ts.map