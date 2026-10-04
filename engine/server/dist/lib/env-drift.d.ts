export interface EnvDriftReport {
    missingDocumentedDefaults: string[];
    unknownKeys: string[];
}
export interface EnvDriftPaths {
    envPath?: string;
    examplePath?: string;
}
export declare function defaultEnvDriftPaths(): Required<EnvDriftPaths>;
export declare function parseEnvNames(text: string, opts?: {
    includeCommented?: boolean;
}): string[];
export declare function compareEnvText(envText: string, exampleText: string): EnvDriftReport;
export declare function formatEnvDriftReport(report: EnvDriftReport): string[];
export declare function checkEnvDrift(paths?: EnvDriftPaths): EnvDriftReport | null;
export declare function warnOnEnvDrift(paths?: EnvDriftPaths, logger?: Pick<Console, 'warn'>): EnvDriftReport | null;
//# sourceMappingURL=env-drift.d.ts.map