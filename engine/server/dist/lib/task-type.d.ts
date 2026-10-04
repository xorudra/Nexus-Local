import type { Request } from 'express';
import type { ChatMessage } from '@freellmapi/shared/types.js';
export type TaskType = 'code' | 'chat' | 'auto';
export declare const TASK_TYPE_HEADER = "x-freellm-task-type";
/** Read the client-declared task type from the request header (default 'auto'). */
export declare function parseTaskTypeHeader(req: Request): TaskType;
/** Derive a concrete task type from the request shape. Bounded, never throws. */
export declare function deriveTaskType(tools: unknown[] | undefined, messages: ChatMessage[] | undefined): 'code' | 'chat';
/**
 * Resolve the effective task bias for a request: the explicit header wins;
 * `auto` falls back to derivation. Returns undefined when there is no signal
 * worth biasing for — callers then leave the routing weights untouched, so the
 * default behaviour is unchanged. `auto` only ever biases UP toward `code`:
 * `chat` is the ordinary case, and silently re-weighting the bulk of traffic
 * in `auto` mode would defeat the point of an opt-in knob.
 */
export declare function resolveTaskType(req: Request, tools: unknown[] | undefined, messages: ChatMessage[] | undefined): 'code' | 'chat' | undefined;
//# sourceMappingURL=task-type.d.ts.map