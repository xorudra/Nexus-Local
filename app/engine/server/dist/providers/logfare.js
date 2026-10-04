import { providerHttpError } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
function checkModel(requested, returned) {
    if (!returned || returned !== requested) {
        throw Object.assign(new Error('Logfare returned a different or missing model identity'), { status: 502 });
    }
}
export class LogfareProvider extends OpenAICompatProvider {
    async validationResult(response) {
        if (!response.ok && ![401, 403].includes(response.status)) {
            throw providerHttpError(response, 'Logfare key validation is temporarily inconclusive');
        }
        return super.validationResult(response);
    }
    constructor() {
        // Responses carry `reasoning_content` (handled by the shared fold) and an
        // extra `neurons` usage field that is passed through untouched. Premium
        // routes answer 403 and surface as a provider error, never as a retry.
        super({ platform: 'logfare', name: 'Logfare', baseUrl: 'https://logfare.ai/v1' });
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
//# sourceMappingURL=logfare.js.map