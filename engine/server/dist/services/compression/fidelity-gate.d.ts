import type { ChatMessage } from '@freellmapi/shared/types.js';
export interface FidelityResult {
    accepted: boolean;
    reason?: 'inflation' | 'fidelity';
    protectedTokenSurvival: number;
    numericLiteralsPreserved: boolean;
    jsonKeySurvival: number;
    diffHunksPreserved: boolean;
    criticalLinesPreserved: boolean;
}
export declare function checkFidelity(before: ChatMessage[], after: ChatMessage[]): FidelityResult;
//# sourceMappingURL=fidelity-gate.d.ts.map