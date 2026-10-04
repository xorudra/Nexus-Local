export interface ProviderReportedSize {
    tokens: number;
    kind: 'input' | 'total';
}
export declare function parseProviderReportedSize(platform: string, message: string | null | undefined): ProviderReportedSize | null;
//# sourceMappingURL=provider-size-parser.d.ts.map