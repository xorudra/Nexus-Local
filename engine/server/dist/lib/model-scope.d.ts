/**
 * Parse a stored scope into a Set for O(1) membership tests, or null when the
 * key is unscoped. Called once per key ROW, never per comparison. An empty or
 * corrupt value degrades to unscoped rather than silently benching the key.
 */
export declare function parseModelScope(json: string | null | undefined): Set<string> | null;
/** Whether a key with this parsed scope may serve the model. */
export declare function scopeAllows(scope: Set<string> | null, modelId: string): boolean;
//# sourceMappingURL=model-scope.d.ts.map