import type { ChatMessage } from '@freellmapi/shared/types.js';
import './engines/index.js';
import type { CompressRequestOptions, CompressionResult } from './types.js';
export declare function compressRequest(messages: ChatMessage[], options?: CompressRequestOptions): CompressionResult;
export declare function formatCompressionHeader(result: CompressionResult): string;
export declare function _clearPrefixFreezeForTesting(): void;
//# sourceMappingURL=pipeline.d.ts.map