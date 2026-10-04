import type { ReasoningEffort } from '../lib/sampling-params.js';
export declare const anthropicRouter: import("express-serve-static-core").Router;
export declare function effortFromAnthropicThinking(thinking: {
    type?: string;
    budget_tokens?: number;
} | null | undefined): ReasoningEffort | undefined;
//# sourceMappingURL=anthropic.d.ts.map