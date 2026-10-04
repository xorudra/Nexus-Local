import { providerHttpError } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
function checkModel(requested, returned) {
    if (!returned || returned !== requested) {
        throw Object.assign(new Error('Api.Airforce returned a different or missing model identity'), { status: 502 });
    }
}
export class AirforceProvider extends OpenAICompatProvider {
    async validationResult(response) {
        if (!response.ok && ![401, 403].includes(response.status)) {
            throw providerHttpError(response, 'Api.Airforce key validation is temporarily inconclusive');
        }
        return super.validationResult(response);
    }
    constructor() {
        // One request per minute per account: a 429 carries Retry-After and is
        // surfaced as-is so the router backs off instead of retrying into it.
        super({ platform: 'airforce', name: 'Api.Airforce', baseUrl: 'https://api.airforce/v1' });
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
//# sourceMappingURL=airforce.js.map