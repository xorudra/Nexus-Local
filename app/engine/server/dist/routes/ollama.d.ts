import type { Request } from 'express';
export declare const ollamaRouter: import("express-serve-static-core").Router;
export type OllamaEmulationMode = 'off' | 'open-loopback' | 'key-required';
export declare function getOllamaEmulationMode(): OllamaEmulationMode;
export declare function isLoopback(req: Request): boolean;
export declare function normalizeOllamaModel(name: string | undefined): string;
//# sourceMappingURL=ollama.d.ts.map