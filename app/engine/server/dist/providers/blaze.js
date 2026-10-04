import { providerHttpError } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
function checkModel(requested, returned) {
    if (!returned || returned !== requested) {
        throw Object.assign(new Error('BlazeAPI returned a different or missing model identity'), { status: 502 });
    }
}
export class BlazeProvider extends OpenAICompatProvider {
    async validationResult(response) {
        if (!response.ok && ![401, 403].includes(response.status)) {
            throw providerHttpError(response, 'BlazeAPI key validation is temporarily inconclusive');
        }
        return super.validationResult(response);
    }
    constructor() {
        // Despite its name, /paid/v1 is also the documented Free-plan endpoint.
        // Named catalog routes only: no fallback to a paid or automatic route.
        super({ platform: 'blaze', name: 'BlazeAPI', baseUrl: 'https://api.blazeapi.org/paid/v1',
            validateUrl: 'https://api.blazeapi.org/paid/v1/usage' });
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
//# sourceMappingURL=blaze.js.map