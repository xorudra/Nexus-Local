import type { Request, Response } from 'express';
import type { ChatMessage, ChatToolCall, ChatToolChoice, ChatToolDefinition } from '@freellmapi/shared/types.js';
import { type RouteResult } from '../services/router.js';
import type { CompletionOptions } from '../providers/base.js';
export interface InboundChatRequest {
    model?: string;
    messages: ChatMessage[];
    stream: boolean;
    maxTokens?: number;
    temperature?: number;
    topP?: number;
    stop?: string | string[];
    tools?: ChatToolDefinition[];
    toolChoice?: ChatToolChoice;
    parallelToolCalls?: boolean;
    topK?: number;
    responseFormat?: CompletionOptions['response_format'];
    reasoningEffort?: CompletionOptions['reasoning_effort'];
    sessionId?: string;
    endpoint: string;
}
export interface InboundChatResult {
    route: RouteResult;
    text: string;
    reasoning: string;
    toolCalls: ChatToolCall[];
    finishReason: string | null;
    promptTokens: number;
    completionTokens: number;
}
export interface InboundChatWire {
    sendError(res: Response, status: number, message: string, code?: string): void;
    sendNonStream(res: Response, result: InboundChatResult): void;
    startStream(res: Response, route: RouteResult): void;
    sendTextDelta(res: Response, route: RouteResult, text: string): void;
    sendReasoningDelta?(res: Response, route: RouteResult, text: string): void;
    sendToolCalls?(res: Response, route: RouteResult, calls: ChatToolCall[]): void;
    finishStream(res: Response, result: InboundChatResult): void;
    sendStreamError?(res: Response, message: string): void;
}
/**
 * Provider-neutral execution for non-OpenAI inbound protocols. The protocol
 * router owns validation and wire translation; this function owns the same
 * routing, retry, cooldown, accounting, pinning, and disconnect behavior as
 * the established OpenAI/Anthropic/Responses surfaces.
 */
export declare function runInboundChat(req: Request, res: Response, input: InboundChatRequest, wire: InboundChatWire): Promise<void>;
//# sourceMappingURL=inbound-chat.d.ts.map