import type { ChatMessage, ChatToolChoice, ChatToolDefinition } from '@freellmapi/shared/types.js';
import type { ReasoningEffort, ResponseFormat } from './sampling-params.js';
import type { InboundChatResult } from './inbound-chat.js';
export interface GeminiPart {
    text?: string;
    thought?: boolean;
    inlineData?: {
        mimeType?: string;
        data?: string;
    };
    inline_data?: {
        mime_type?: string;
        data?: string;
    };
    functionCall?: {
        id?: string;
        name?: string;
        args?: unknown;
    };
    functionResponse?: {
        id?: string;
        name?: string;
        response?: unknown;
    };
    thoughtSignature?: string;
    [key: string]: unknown;
}
export interface GeminiContent {
    role?: 'user' | 'model';
    parts?: GeminiPart[];
}
export interface GeminiInboundRequest {
    contents: GeminiContent[];
    systemInstruction?: {
        parts?: GeminiPart[];
    };
    tools?: Array<{
        functionDeclarations?: Array<{
            name?: string;
            description?: string;
            parameters?: Record<string, unknown>;
            parametersJsonSchema?: Record<string, unknown>;
        }>;
    }>;
    toolConfig?: {
        functionCallingConfig?: {
            mode?: string;
            allowedFunctionNames?: string[];
        };
    };
    generationConfig?: {
        temperature?: number;
        topP?: number;
        topK?: number;
        maxOutputTokens?: number;
        stopSequences?: string[];
        responseMimeType?: string;
        responseSchema?: Record<string, unknown>;
        responseJsonSchema?: Record<string, unknown>;
        thinkingConfig?: {
            thinkingBudget?: number;
        };
    };
}
export declare function normalizeGeminiSchema(schema: unknown): unknown;
export declare function sanitizeForGemini(schema: unknown): unknown;
export declare function geminiContentsToMessages(body: GeminiInboundRequest): ChatMessage[];
export declare function geminiToolsToChatTools(tools: GeminiInboundRequest['tools']): ChatToolDefinition[] | undefined;
export declare function geminiToolChoice(config: GeminiInboundRequest['toolConfig']): ChatToolChoice | undefined;
export declare function geminiResponseFormat(config: GeminiInboundRequest['generationConfig']): ResponseFormat | undefined;
export declare function effortFromGeminiThinking(config: GeminiInboundRequest['generationConfig']): ReasoningEffort | undefined;
export declare function geminiFinishReason(finishReason: string | null, hasToolCalls?: boolean): string;
export declare function geminiPartsFromResult(result: Pick<InboundChatResult, 'text' | 'reasoning' | 'toolCalls'>): GeminiPart[];
export declare function geminiResponseFromResult(result: InboundChatResult): Record<string, unknown>;
export declare function estimateGeminiTokens(body: Pick<GeminiInboundRequest, 'contents' | 'systemInstruction' | 'tools'>): number;
//# sourceMappingURL=gemini-wire.d.ts.map