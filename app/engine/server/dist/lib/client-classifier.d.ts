import type { Request } from 'express';
export declare const CLIENT_AGENTS: readonly ["claude-code", "codex", "cline", "roo", "continue", "aider", "opencode", "goose", "qwen-code", "kilo-code", "crush", "deepseek-harness", "mimo-code", "atomcode", "openclaw", "hermes-agent", "cursor", "gemini-cli", "zed", "jetbrains", "ollama-client", "openai-sdk", "anthropic-sdk", "unknown"];
export type ClientAgent = (typeof CLIENT_AGENTS)[number];
/**
 * Best-effort classifier from stable protocol/header signals first, then UA.
 * It intentionally returns a coarse enum: analytics should remain useful when
 * a client revs its version string or wraps an underlying SDK.
 */
export declare function classifyClientAgent(req: Request): ClientAgent;
//# sourceMappingURL=client-classifier.d.ts.map