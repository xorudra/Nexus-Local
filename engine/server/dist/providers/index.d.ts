import type { Platform } from '@freellmapi/shared/types.js';
import type { BaseProvider } from './base.js';
export declare function getProvider(platform: Platform): BaseProvider | undefined;
/**
 * Resolve the provider for a route. Built-in platforms return their registered
 * singleton; the 'custom' platform builds a fresh OpenAICompatProvider bound to
 * the caller-supplied base URL (stored per api_keys row). Returns undefined for
 * a custom provider with no base URL configured.
 */
export declare function resolveProvider(platform: Platform, baseUrl?: string | null): BaseProvider | undefined;
export declare function getAllProviders(): BaseProvider[];
export declare function hasProvider(platform: Platform): boolean;
//# sourceMappingURL=index.d.ts.map