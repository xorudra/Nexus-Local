/**
 * Inline tool-call dialect rescue (#231 audit).
 *
 * When a conversation switches models mid-task (failover, sticky miss), the
 * new model often continues the previous model's tool-call style and emits
 * the call as TEXT in its private training dialect instead of a structured
 * `tool_calls` array. The client's agent loop sees prose, treats the turn as
 * a final answer, and dies mid-task — observed live with the OpenAI Agents
 * SDK when Kimi-K2.6 continued a DeepSeek history:
 *
 *   <|tool_calls_section_begin|> <|tool_call_begin|> chatcmpl-tool-bde5...
 *
 * This module detects the known dialects and re-parses them into standard
 * OpenAI tool_calls, schema-gated against the request's tool list. A turn
 * that is detected as a dialect but cannot be parsed into a known tool is a
 * DEAD turn — the caller fails over instead of delivering gibberish.
 *
 * Supported dialects:
 *  1. Kimi / DeepSeek token style:
 *     <|tool_calls_section_begin|><|tool_call_begin|>functions.NAME:0
 *     <|tool_call_argument_begin|>{...}<|tool_call_end|>...
 *  2. Llama / Groq function tags: <function=NAME{...}</function> and
 *     <function=NAME>{...}</function>
 *  3. Qwen / Hermes XML: <tool_call>{"name": ..., "arguments": ...}</tool_call>
 *  4. Bare or ```json-fenced single JSON object: {"name": KNOWN, "arguments": {...}}
 *     (only rescued when "name" matches a requested tool — bare JSON is a
 *     legitimate answer shape, so this one is strictly schema-gated)
 */
export interface RescuedToolCall {
    name: string;
    /** JSON string, exactly like OpenAI's function.arguments */
    arguments: string;
}
export interface RescueResult {
    /** True when the text contains inline tool-call dialect markers. */
    detected: boolean;
    /** Parsed calls; null when detected but unparseable (dead turn). */
    calls: RescuedToolCall[] | null;
    /** Text with the dialect blocks removed (may be ''). */
    cleanText: string;
}
/** Does the (trimmed) text start with a known dialect marker? */
export declare function startsWithDialectMarker(text: string): boolean;
/**
 * Streaming hold-window helper: could `text` still grow into a dialect
 * marker? True while text is a strict prefix of some marker (e.g. "<|too"),
 * so the stream loop keeps holding; once this and startsWithDialectMarker
 * are both false the text is ordinary prose and can be flushed.
 */
export declare function couldBecomeDialectMarker(text: string): boolean;
/** Anywhere-in-text detection for the non-streaming path. */
export declare function containsDialectMarker(text: string): boolean;
/**
 * Rescue inline tool-call dialects out of an assistant text answer.
 *
 * @param text       the assistant message content
 * @param toolNames  the names of the tools the REQUEST declared; rescued
 *                   calls must match one (empty set = accept any name,
 *                   used by tests only)
 */
export declare function rescueInlineToolCalls(text: string, toolNames: Set<string>): RescueResult;
//# sourceMappingURL=tool-call-rescue.d.ts.map