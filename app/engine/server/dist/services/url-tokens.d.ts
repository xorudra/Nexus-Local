export interface UrlTokenRow {
    id: number;
    label: string;
    tokenPrefix: string;
    createdAt: string;
    lastUsedAt: string | null;
    revokedAt: string | null;
}
export declare function listUrlTokens(): UrlTokenRow[];
export declare function mintUrlToken(label: string): UrlTokenRow & {
    token: string;
};
export declare function revokeUrlToken(id: number): boolean;
export declare function validateUrlToken(token: string): boolean;
//# sourceMappingURL=url-tokens.d.ts.map