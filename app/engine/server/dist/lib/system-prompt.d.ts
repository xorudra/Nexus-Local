import type { ChatMessage } from '@freellmapi/shared/types.js';
export declare const CLIENT_PROFILE_KEY_PREFIX = "sk-cp-";
export declare function timingSafeStringEqual(provided: string, expected: string): boolean;
export declare function mintClientProfileKey(): string;
export declare function hashClientProfileKey(key: string): string;
export type ResolvedAuth = {
    kind: 'unified';
    systemPrompt: null;
} | {
    kind: 'profile';
    profileId: number;
    name: string;
    systemPrompt: string | null;
};
/**
 * Resolve an inference credential. The unified key maps to today's behavior
 * (no enforced prompt); a client-profile key carries its own prompt; a
 * disabled profile is rejected exactly like an unknown key so a revoked
 * client can't distinguish "disabled" from "deleted".
 */
export declare function resolveAuth(token: string | undefined): ResolvedAuth | null;
/**
 * Prepend the server-enforced system prompt. It goes FIRST, ahead of any
 * caller-supplied system message, so the enforced instructions take priority
 * while the caller's own system message is preserved after it — the caller
 * can add context but cannot override or remove the profile's prompt.
 * An empty/null prompt is a neutral passthrough: nothing is injected.
 */
export declare function prependSystemPrompt(messages: ChatMessage[], prompt: string | null | undefined): ChatMessage[];
//# sourceMappingURL=system-prompt.d.ts.map