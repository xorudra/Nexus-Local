import { BaseProvider, providerHttpError } from './base.js';
export const SPEECHIFY_BASE_URL = 'https://api.speechify.ai/v1';
export const SPEECHIFY_VERSION = '2026-09-08';
/** Speechify is TTS-only. Synthesis is dispatched by services/media.ts;
 * registration here provides credential management, not a fake chat API. */
export class SpeechifyProvider extends BaseProvider {
    platform = 'speechify';
    name = 'Speechify';
    async validateKey(apiKey) {
        const response = await this.fetchWithTimeout(`${SPEECHIFY_BASE_URL}/workspaces/current/entitlements`, {
            method: 'GET',
            headers: { Authorization: `Bearer ${apiKey}`, 'Speechify-Version': SPEECHIFY_VERSION },
        });
        if (!response.ok && ![401, 403].includes(response.status)) {
            throw providerHttpError(response, 'Speechify key validation is temporarily inconclusive');
        }
        return this.validationResult(response);
    }
    async chatCompletion() {
        throw Object.assign(new Error('Speechify supports /v1/audio/speech, not chat completions'), { status: 400 });
    }
    // An unsupported operation must reject before yielding any stream data.
    // eslint-disable-next-line require-yield
    async *streamChatCompletion() {
        throw Object.assign(new Error('Speechify supports /v1/audio/speech, not chat completions'), { status: 400 });
    }
}
//# sourceMappingURL=speechify.js.map