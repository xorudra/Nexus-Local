import type { CompletionOptions } from './base.js';
import { OpenAICompatProvider } from './openai-compat.js';
export declare class ExperientialProvider extends OpenAICompatProvider {
    constructor();
    protected samplingForModel(modelId: string, options?: CompletionOptions): {
        temperature: number | undefined;
        topP: number | undefined;
    };
}
//# sourceMappingURL=experiential.d.ts.map