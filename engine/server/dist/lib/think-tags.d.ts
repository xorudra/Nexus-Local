import type { ChatCompletionChunk } from '@freellmapi/shared/types.js';
export interface ThinkSplit {
    content: string;
    reasoning: string;
}
export declare class ThinkTagStreamFilter {
    private state;
    private pending;
    /** Feed a text delta; returns the content/reasoning to emit for it. */
    push(text: string): ThinkSplit;
    /** Stream ended: release whatever is held. Unclosed `<think>` flushes as
     *  reasoning; an undecided lead buffer flushes as content. */
    flush(): ThinkSplit;
}
/** Non-streaming split of a complete message body. Returns the original text
 *  as `content` (reasoning: '') when the message doesn't open with `<think>`. */
export declare function splitThinkTag(text: string): ThinkSplit;
/**
 * In-place extraction for a non-streaming choice message: moves a leading
 * `<think>…</think>` block out of `content` into `reasoning_content`
 * (appending when the provider already set one). No-op for messages without
 * an opening tag, so no-knob/no-tag responses are byte-identical.
 */
export declare function extractThinkFromMessage(msg: {
    content?: unknown;
    reasoning_content?: string;
}): void;
/**
 * Streaming wrapper: rewrites `choices[0].delta.content` through the filter,
 * emitting extracted reasoning as `delta.reasoning_content` on the same
 * chunk. Chunks without text (role preambles, tool_call deltas, usage frames,
 * native reasoning deltas) pass through untouched. When the source ends with
 * held bytes (unclosed tag / undecided prefix) a final synthetic chunk
 * carries them, so text is never lost.
 */
export declare function extractThinkTagsFromStream(source: AsyncGenerator<ChatCompletionChunk>): AsyncGenerator<ChatCompletionChunk>;
//# sourceMappingURL=think-tags.d.ts.map