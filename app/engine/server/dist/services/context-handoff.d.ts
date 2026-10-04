import type { ChatMessage } from '@freellmapi/shared/types.js';
export type ContextHandoffMode = 'off' | 'on_model_switch';
export declare const HANDOFF_MAX_TOKENS: number;
export declare function getContextHandoffMode(): ContextHandoffMode;
export declare function recordIncomingMessages(sessionKey: string, messages: ChatMessage[]): void;
export declare function hasPriorModel(sessionKey: string): boolean;
export declare function maybeInjectContextHandoff(params: {
    mode: ContextHandoffMode;
    sessionKey: string;
    messages: ChatMessage[];
    selectedModelKey: string;
}): {
    messages: ChatMessage[];
    injected: boolean;
    injectedTokens: number;
};
export declare function recordSuccessfulModel(params: {
    sessionKey: string;
    modelKey: string;
}): void;
export declare function _clearStoreForTesting(): void;
//# sourceMappingURL=context-handoff.d.ts.map