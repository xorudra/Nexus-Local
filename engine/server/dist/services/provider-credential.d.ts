export interface ReservedProviderCredential {
    id: number;
    key: string;
    baseUrl: string | null;
    release: () => void;
}
/** Select and reserve a credential for the independent embeddings/media routers.
 * Bound custom models stay on their own key; ordinary providers may use any
 * healthy key with room in its budget. Callers release after logging the result.
 */
export declare function reserveProviderCredential(row: {
    platform: string;
    key_id: number | null;
}, estimatedTokens: number, skip?: (keyId: number) => boolean): {
    credential: ReservedProviderCredential | null;
    budgetBlocked: boolean;
};
//# sourceMappingURL=provider-credential.d.ts.map