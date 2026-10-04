import type { CompressionEngine } from './types.js';
export declare function registerEngine(engine: CompressionEngine): void;
export declare function getEngine(id: string): CompressionEngine | undefined;
export declare function getRegisteredEngines(): CompressionEngine[];
export declare function _clearRegistryForTesting(): void;
//# sourceMappingURL=registry.d.ts.map