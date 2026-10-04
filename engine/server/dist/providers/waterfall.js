import { providerHttpError } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
function checkModel(requested, returned) {
    if (!returned || returned !== requested) {
        throw Object.assign(new Error('Waterfall returned a different or missing model identity'), { status: 502 });
    }
}
export class WaterfallProvider extends OpenAICompatProvider {
    async validationResult(response) {
        if (!response.ok && ![401, 403].includes(response.status)) {
            throw providerHttpError(response, 'Waterfall key validation is temporarily inconclusive');
        }
        return super.validationResult(response);
    }
    constructor() {
        // Upstream outages arrive as 503 with a structured `detail` object
        // ({"type":"waterfall_transport_error","code":"upstream_unavailable"});
        // the shared error path keeps the status and falls back to statusText.
        super({ platform: 'waterfall', name: 'Waterfall', baseUrl: 'https://api.getwaterfall.org/v1' });
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
//# sourceMappingURL=waterfall.js.map