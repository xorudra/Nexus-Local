import type { ChatMessage } from '@freellmapi/shared/types.js';
export type ContentTextBlock = {
    type: 'text';
    text: string;
};
export type ContentBlock = ContentTextBlock | {
    type: string;
    [key: string]: unknown;
};
export declare function contentToString(content: unknown): string;
export declare function flattenMessageContent(messages: ChatMessage[]): ChatMessage[];
export declare function contentHasImage(content: unknown): boolean;
export declare function messageHasImage(messages: ChatMessage[]): boolean;
export declare function contentHasVideo(content: unknown): boolean;
export declare function messageHasVideo(messages: ChatMessage[]): boolean;
export declare function stripImagesFromMessages(messages: ChatMessage[]): ChatMessage[];
export declare const GITHUB_MAX_INPUT_TOKENS = 7500;
/**
 * Fit a message list inside GitHub Models' input ceiling before dispatch.
 * Keeps the leading system prompt verbatim (its instructions are the whole
 * point of prepending one) and then as many of the NEWEST messages as the
 * remaining budget allows, dropping the oldest turns first — the same trade a
 * client's own context window makes. A single message that blows the budget on
 * its own is truncated rather than dropped, so the turn is never dispatched
 * with nothing to answer.
 *
 * Returns the ORIGINAL array when the request already fits, which is both the
 * common case and the cheap one: callers can hand every github-routed request
 * through here without copying anything.
 */
export declare function truncateMessagesForGithub(messages: ChatMessage[], budget?: number): ChatMessage[];
export declare function sanitizeResponse<T>(payload: T): T;
export declare function normalizeOutboundContent<T>(payload: T): T;
//# sourceMappingURL=content.d.ts.map