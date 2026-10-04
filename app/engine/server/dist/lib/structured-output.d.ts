export type JsonEnforcement = {
    ok: true;
    content: string;
    healed: boolean;
} | {
    ok: false;
};
export declare function enforceJsonContent(content: string): JsonEnforcement;
//# sourceMappingURL=structured-output.d.ts.map