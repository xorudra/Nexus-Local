import type { ChatMessage } from '@freellmapi/shared/types.js';
import type { ToolCallOrigin } from './types.js';
export declare function textContent(message: ChatMessage): string | null;
export declare function withTextContent(message: ChatMessage, content: string): ChatMessage;
export declare function messageChars(messages: ChatMessage[]): number;
export declare function estimateTokensFromChars(chars: number): number;
export declare function buildToolCallOrigins(messages: ChatMessage[]): Map<string, ToolCallOrigin>;
export declare function allMessageText(messages: ChatMessage[]): string;
//# sourceMappingURL=helpers.d.ts.map