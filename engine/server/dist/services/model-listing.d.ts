export interface NormalizedModel {
    id: string;
    name: string;
    ownedBy: string;
    available: number;
    enabled: number;
    contextWindow: number | null;
    intel: number;
    platforms: string[];
    supportsTools: boolean;
    executionStatus: 'ready' | 'needsKey' | 'exhausted';
}
export interface ModelListing {
    models: NormalizedModel[];
    autoContextWindow: number | null;
}
export declare function buildModelListing(): ModelListing;
//# sourceMappingURL=model-listing.d.ts.map