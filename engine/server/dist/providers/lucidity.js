import { providerHttpError } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
function checkModel(requested, returned) {
    // Catalog routes carry a `:free` suffix that the response omits, and the
    // `lucidityai/synth-2.5-*:free` routes legitimately report the gateway's
    // own `synth-2.5-preview`. Anything else (including the `open/*` routes
    // observed silently answering as synth-2.5-preview) is a substitution.
    const accepted = typeof returned === 'string' && returned.length > 0 && (returned === requested ||
        returned === requested.replace(/:free$/, '') ||
        (requested.startsWith('lucidityai/synth-') && returned.startsWith('synth-')));
    if (!accepted) {
        throw Object.assign(new Error('Lucidity Composite returned a different or missing model identity'), { status: 502 });
    }
}
export class LucidityProvider extends OpenAICompatProvider {
    async validationResult(response) {
        if (!response.ok && ![401, 403].includes(response.status)) {
            throw providerHttpError(response, 'Lucidity Composite key validation is temporarily inconclusive');
        }
        return super.validationResult(response);
    }
    constructor() {
        super({ platform: 'lucidity', name: 'Lucidity Composite', baseUrl: 'https://composite.lucidity.sh/v1' });
    }
    async chatCompletion(apiKey, messages, modelId, options, quotaContext) {
        const response = await super.chatCompletion(apiKey, messages, modelId, options, quotaContext);
        checkModel(modelId, response.model);
        return response;
    }
    async *streamChatCompletion(apiKey, messages, modelId, options, quotaContext) {
        for await (const chunk of super.streamChatCompletion(apiKey, messages, modelId, options, quotaContext)) {
            checkModel(modelId, chunk.model);
            yield chunk;
        }
    }
}
//# sourceMappingURL=lucidity.js.map