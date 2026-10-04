export declare const openapiSpec: {
    readonly openapi: "3.0.3";
    readonly info: {
        readonly title: "FreeLLMAPI";
        readonly version: "0.4.1";
        readonly description: string;
        readonly license: {
            readonly name: "MIT";
            readonly url: "https://github.com/tashfeenahmed/freellmapi/blob/main/LICENSE";
        };
    };
    readonly servers: readonly [{
        readonly url: "/";
        readonly description: "This proxy instance";
    }];
    readonly security: readonly [{
        readonly bearerAuth: readonly [];
    }, {
        readonly apiKeyAuth: readonly [];
    }];
    readonly tags: readonly [{
        readonly name: "Chat";
        readonly description: "OpenAI-compatible chat and completion endpoints";
    }, {
        readonly name: "Media";
        readonly description: "Image generation and text-to-speech";
    }, {
        readonly name: "Responses";
        readonly description: "OpenAI Responses API (Codex CLI wire format)";
    }, {
        readonly name: "Anthropic";
        readonly description: "Anthropic Messages API (Claude Code and the Anthropic SDKs)";
    }, {
        readonly name: "Models";
        readonly description: "Model discovery";
    }, {
        readonly name: "Gemini";
        readonly description: "Native Gemini generateContent wire format";
    }, {
        readonly name: "Ollama";
        readonly description: "Opt-in Ollama-compatible local-client surface";
    }, {
        readonly name: "URL tokens";
        readonly description: "Headerless-client aliases using separately revocable URL tokens";
    }];
    readonly paths: {
        readonly '/v1/chat/completions': {
            readonly post: {
                readonly tags: readonly ["Chat"];
                readonly operationId: "createChatCompletion";
                readonly summary: "Create a chat completion";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/ChatCompletionRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: string;
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/ChatCompletionResponse";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/completions': {
            readonly post: {
                readonly tags: readonly ["Chat"];
                readonly operationId: "createCompletion";
                readonly summary: "Create a legacy text completion";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/CompletionRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "A text completion (`object: \"text_completion\"`), or an SSE stream when `stream: true`.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/CompletionResponse";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/embeddings': {
            readonly post: {
                readonly tags: readonly ["Chat"];
                readonly operationId: "createEmbedding";
                readonly summary: "Create embeddings";
                readonly description: "OpenAI-compatible embeddings. `input` accepts a string or an array of strings.";
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/EmbeddingRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "A list of embedding vectors.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/EmbeddingResponse";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/images/generations': {
            readonly post: {
                readonly tags: readonly ["Media"];
                readonly operationId: "createImage";
                readonly summary: "Generate images";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/ImageRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "Generated image(s), as URLs or base64 depending on `response_format`.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/ImageResponse";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/videos/generations': {
            readonly post: {
                readonly tags: readonly ["Media"];
                readonly operationId: "createVideo";
                readonly summary: "Generate video";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/VideoRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "The generated video.";
                        readonly content: {
                            readonly 'video/mp4': {
                                readonly schema: {
                                    readonly type: "string";
                                    readonly format: "binary";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/audio/speech': {
            readonly post: {
                readonly tags: readonly ["Media"];
                readonly operationId: "createSpeech";
                readonly summary: "Generate speech (text-to-speech)";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/SpeechRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "Raw audio bytes.";
                        readonly content: {
                            readonly 'audio/mpeg': {
                                readonly schema: {
                                    readonly type: "string";
                                    readonly format: "binary";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/audio/transcriptions': {
            readonly post: {
                readonly tags: readonly ["Media"];
                readonly operationId: "createTranscription";
                readonly summary: "Transcribe audio (speech-to-text)";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'multipart/form-data': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/TranscriptionRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "The transcription in the requested format.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly text: {
                                            readonly type: "string";
                                        };
                                    };
                                };
                            };
                            readonly 'text/plain': {
                                readonly schema: {
                                    readonly type: "string";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '413': {
                        readonly description: "The uploaded audio exceeds the 25 MB limit.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/Error";
                                };
                            };
                        };
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                    readonly '503': {
                        readonly description: "No transcription models synced yet (code 'no_transcription_models'): the registry arrives via catalog sync.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/Error";
                                };
                            };
                        };
                    };
                };
            };
        };
        readonly '/v1/responses': {
            readonly post: {
                readonly tags: readonly ["Responses"];
                readonly operationId: "createResponse";
                readonly summary: "Create a model response (OpenAI Responses API)";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/ResponseRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "A response object, or an SSE stream of Responses events when `stream: true`.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/ResponseObject";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/messages': {
            readonly post: {
                readonly tags: readonly ["Anthropic"];
                readonly operationId: "createMessage";
                readonly summary: "Create a message (Anthropic Messages API)";
                readonly description: string;
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/AnthropicMessageRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "An Anthropic message, or an SSE stream of Anthropic events when `stream: true`.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/AnthropicMessageResponse";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                    readonly '429': {
                        readonly $ref: "#/components/responses/RateLimited";
                    };
                    readonly '502': {
                        readonly $ref: "#/components/responses/UpstreamError";
                    };
                };
            };
        };
        readonly '/v1/messages/count_tokens': {
            readonly post: {
                readonly tags: readonly ["Anthropic"];
                readonly operationId: "countTokens";
                readonly summary: "Count input tokens (Anthropic Messages API)";
                readonly description: "Estimates the input token count for an Anthropic Messages request without running it.";
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/AnthropicMessageRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "An estimated input token count.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/CountTokensResponse";
                                };
                            };
                        };
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                };
            };
        };
        readonly '/v1/models': {
            readonly get: {
                readonly tags: readonly ["Models"];
                readonly operationId: "listModels";
                readonly summary: "List available models";
                readonly description: string;
                readonly parameters: readonly [{
                    readonly name: "available";
                    readonly in: "query";
                    readonly required: false;
                    readonly description: "When `true`, return only models that are currently usable.";
                    readonly schema: {
                        readonly type: "boolean";
                    };
                }];
                readonly responses: {
                    readonly '200': {
                        readonly description: "The model list.";
                        readonly content: {
                            readonly 'application/json': {
                                readonly schema: {
                                    readonly $ref: "#/components/schemas/ModelList";
                                };
                            };
                        };
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                };
            };
        };
        readonly '/v1beta/models': {
            readonly get: {
                readonly tags: readonly ["Gemini"];
                readonly operationId: "listGeminiModels";
                readonly summary: "List models in Gemini format";
                readonly security: readonly [{
                    readonly googleApiKeyHeader: readonly [];
                }, {
                    readonly googleApiKeyQuery: readonly [];
                }, {
                    readonly bearerAuth: readonly [];
                }];
                readonly responses: {
                    readonly '200': {
                        readonly description: "Gemini-shaped model list.";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                };
            };
        };
        readonly '/v1beta/models/{model}': {
            readonly get: {
                readonly tags: readonly ["Gemini"];
                readonly operationId: "getGeminiModel";
                readonly summary: "Get Gemini-shaped model metadata";
                readonly security: readonly [{
                    readonly googleApiKeyHeader: readonly [];
                }, {
                    readonly googleApiKeyQuery: readonly [];
                }, {
                    readonly bearerAuth: readonly [];
                }];
                readonly parameters: readonly [{
                    readonly name: "model";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly responses: {
                    readonly '200': {
                        readonly description: "Gemini-shaped model metadata.";
                    };
                    readonly '404': {
                        readonly description: "Model not found.";
                    };
                };
            };
        };
        readonly '/v1beta/models/{model}:generateContent': {
            readonly post: {
                readonly tags: readonly ["Gemini"];
                readonly operationId: "generateGeminiContent";
                readonly summary: "Generate content using the native Gemini wire format";
                readonly security: readonly [{
                    readonly googleApiKeyHeader: readonly [];
                }, {
                    readonly googleApiKeyQuery: readonly [];
                }, {
                    readonly bearerAuth: readonly [];
                }];
                readonly parameters: readonly [{
                    readonly name: "model";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/GeminiGenerateRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "Gemini candidates and usage metadata.";
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                };
            };
        };
        readonly '/v1beta/models/{model}:streamGenerateContent': {
            readonly post: {
                readonly tags: readonly ["Gemini"];
                readonly operationId: "streamGeminiContent";
                readonly summary: "Stream native Gemini content";
                readonly description: "Use `?alt=sse` for Gemini CLI SSE. Without it, the response is a streamed JSON array.";
                readonly security: readonly [{
                    readonly googleApiKeyHeader: readonly [];
                }, {
                    readonly googleApiKeyQuery: readonly [];
                }, {
                    readonly bearerAuth: readonly [];
                }];
                readonly parameters: readonly [{
                    readonly name: "model";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }, {
                    readonly name: "alt";
                    readonly in: "query";
                    readonly required: false;
                    readonly schema: {
                        readonly type: "string";
                        readonly enum: readonly ["sse"];
                    };
                }];
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/GeminiGenerateRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "SSE or JSON-array Gemini stream.";
                    };
                    readonly '400': {
                        readonly $ref: "#/components/responses/BadRequest";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                };
            };
        };
        readonly '/v1beta/models/{model}:countTokens': {
            readonly post: {
                readonly tags: readonly ["Gemini"];
                readonly operationId: "countGeminiTokens";
                readonly summary: "Estimate tokens for Gemini content";
                readonly security: readonly [{
                    readonly googleApiKeyHeader: readonly [];
                }, {
                    readonly googleApiKeyQuery: readonly [];
                }, {
                    readonly bearerAuth: readonly [];
                }];
                readonly parameters: readonly [{
                    readonly name: "model";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly requestBody: {
                    readonly required: true;
                    readonly content: {
                        readonly 'application/json': {
                            readonly schema: {
                                readonly $ref: "#/components/schemas/GeminiGenerateRequest";
                            };
                        };
                    };
                };
                readonly responses: {
                    readonly '200': {
                        readonly description: "Heuristic token count.";
                    };
                    readonly '401': {
                        readonly $ref: "#/components/responses/Unauthorized";
                    };
                };
            };
        };
        readonly '/api/tags': {
            readonly get: {
                readonly tags: readonly ["Ollama"];
                readonly operationId: "listOllamaModels";
                readonly summary: "List models in Ollama format";
                readonly 'x-optional-surface': true;
                readonly responses: {
                    readonly '200': {
                        readonly description: "Ollama model list.";
                    };
                    readonly '404': {
                        readonly description: "Emulation disabled.";
                    };
                };
            };
        };
        readonly '/api/chat': {
            readonly post: {
                readonly tags: readonly ["Ollama"];
                readonly operationId: "ollamaChat";
                readonly summary: "Create an Ollama chat response";
                readonly description: "Streaming defaults to NDJSON, matching Ollama.";
                readonly 'x-optional-surface': true;
                readonly responses: {
                    readonly '200': {
                        readonly description: "Ollama chat response or NDJSON stream.";
                    };
                    readonly '404': {
                        readonly description: "Emulation disabled.";
                    };
                };
            };
        };
        readonly '/api/generate': {
            readonly post: {
                readonly tags: readonly ["Ollama"];
                readonly operationId: "ollamaGenerate";
                readonly summary: "Create an Ollama legacy prompt response";
                readonly 'x-optional-surface': true;
                readonly responses: {
                    readonly '200': {
                        readonly description: "Ollama generation response or NDJSON stream.";
                    };
                    readonly '404': {
                        readonly description: "Emulation disabled.";
                    };
                };
            };
        };
        readonly '/api/show': {
            readonly post: {
                readonly tags: readonly ["Ollama"];
                readonly operationId: "showOllamaModel";
                readonly summary: "Show Ollama model metadata";
                readonly 'x-optional-surface': true;
                readonly responses: {
                    readonly '200': {
                        readonly description: "Ollama model metadata.";
                    };
                    readonly '404': {
                        readonly description: "Emulation disabled or model missing.";
                    };
                };
            };
        };
        readonly '/api/version': {
            readonly get: {
                readonly tags: readonly ["Ollama"];
                readonly operationId: "getOllamaVersion";
                readonly summary: "Get emulated Ollama version";
                readonly 'x-optional-surface': true;
                readonly responses: {
                    readonly '200': {
                        readonly description: "Emulation version.";
                    };
                    readonly '404': {
                        readonly description: "Emulation disabled.";
                    };
                };
            };
        };
        readonly '/api/embed': {
            readonly post: {
                readonly tags: readonly ["Ollama"];
                readonly operationId: "ollamaEmbed";
                readonly summary: "Create Ollama embeddings";
                readonly 'x-optional-surface': true;
                readonly responses: {
                    readonly '200': {
                        readonly description: "Ollama embedding vectors.";
                    };
                    readonly '404': {
                        readonly description: "Emulation disabled.";
                    };
                };
            };
        };
        readonly '/api/embeddings': {
            readonly post: {
                readonly tags: readonly ["Ollama"];
                readonly operationId: "ollamaLegacyEmbed";
                readonly summary: "Create a legacy Ollama embedding";
                readonly description: "A valid dashboard session falls through to the dashboard embeddings API.";
                readonly 'x-optional-surface': true;
                readonly responses: {
                    readonly '200': {
                        readonly description: "Legacy Ollama embedding.";
                    };
                    readonly '404': {
                        readonly description: "Emulation disabled.";
                    };
                };
            };
        };
        readonly '/v1/t/{token}/models': {
            readonly get: {
                readonly tags: readonly ["URL tokens"];
                readonly operationId: "listModelsWithUrlToken";
                readonly summary: "Headerless model discovery";
                readonly parameters: readonly [{
                    readonly name: "token";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly security: readonly [];
                readonly responses: {
                    readonly '200': {
                        readonly description: "OpenAI-shaped model list.";
                    };
                    readonly '401': {
                        readonly description: "Invalid or revoked URL token.";
                    };
                };
            };
        };
        readonly '/v1/t/{token}/chat/completions': {
            readonly post: {
                readonly tags: readonly ["URL tokens"];
                readonly operationId: "chatWithUrlToken";
                readonly summary: "Headerless OpenAI chat completions";
                readonly description: "URL tokens are separately revocable and are never the unified API key. URLs can leak into history and logs.";
                readonly parameters: readonly [{
                    readonly name: "token";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly security: readonly [];
                readonly responses: {
                    readonly '200': {
                        readonly description: "OpenAI chat completion.";
                    };
                    readonly '401': {
                        readonly description: "Invalid or revoked URL token.";
                    };
                };
            };
        };
        readonly '/v1/t/{token}/responses': {
            readonly post: {
                readonly tags: readonly ["URL tokens"];
                readonly operationId: "responsesWithUrlToken";
                readonly summary: "Headerless OpenAI Responses API";
                readonly parameters: readonly [{
                    readonly name: "token";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly security: readonly [];
                readonly responses: {
                    readonly '200': {
                        readonly description: "OpenAI Responses response.";
                    };
                    readonly '401': {
                        readonly description: "Invalid or revoked URL token.";
                    };
                };
            };
        };
        readonly '/v1/t/{token}/api/chat': {
            readonly post: {
                readonly tags: readonly ["URL tokens"];
                readonly operationId: "ollamaChatWithUrlToken";
                readonly summary: "Headerless Ollama chat";
                readonly parameters: readonly [{
                    readonly name: "token";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly security: readonly [];
                readonly responses: {
                    readonly '200': {
                        readonly description: "Ollama response or NDJSON stream.";
                    };
                    readonly '401': {
                        readonly description: "Invalid or revoked URL token.";
                    };
                };
            };
        };
        readonly '/v1/t/{token}/api/tags': {
            readonly get: {
                readonly tags: readonly ["URL tokens"];
                readonly operationId: "ollamaTagsWithUrlToken";
                readonly summary: "Headerless Ollama model discovery";
                readonly parameters: readonly [{
                    readonly name: "token";
                    readonly in: "path";
                    readonly required: true;
                    readonly schema: {
                        readonly type: "string";
                    };
                }];
                readonly security: readonly [];
                readonly responses: {
                    readonly '200': {
                        readonly description: "Ollama model list.";
                    };
                    readonly '401': {
                        readonly description: "Invalid or revoked URL token.";
                    };
                };
            };
        };
    };
    readonly components: {
        readonly securitySchemes: {
            readonly bearerAuth: {
                readonly type: "http";
                readonly scheme: "bearer";
                readonly description: "Unified API key as `Authorization: Bearer <key>`.";
            };
            readonly apiKeyAuth: {
                readonly type: "apiKey";
                readonly in: "header";
                readonly name: "x-api-key";
                readonly description: "Unified API key as `x-api-key: <key>` (Anthropic-style clients).";
            };
            readonly googleApiKeyHeader: {
                readonly type: "apiKey";
                readonly in: "header";
                readonly name: "x-goog-api-key";
                readonly description: "Unified API key in Gemini SDK format.";
            };
            readonly googleApiKeyQuery: {
                readonly type: "apiKey";
                readonly in: "query";
                readonly name: "key";
                readonly description: "Gemini compatibility fallback. Prefer the header because URLs leak into history and logs.";
            };
        };
        readonly responses: {
            readonly BadRequest: {
                readonly description: "The request was malformed.";
                readonly content: {
                    readonly 'application/json': {
                        readonly schema: {
                            readonly $ref: "#/components/schemas/Error";
                        };
                    };
                };
            };
            readonly Unauthorized: {
                readonly description: "Missing or invalid API key.";
                readonly content: {
                    readonly 'application/json': {
                        readonly schema: {
                            readonly $ref: "#/components/schemas/Error";
                        };
                    };
                };
            };
            readonly RateLimited: {
                readonly description: "Rate limit exceeded.";
                readonly content: {
                    readonly 'application/json': {
                        readonly schema: {
                            readonly $ref: "#/components/schemas/Error";
                        };
                    };
                };
            };
            readonly UpstreamError: {
                readonly description: "Every candidate provider failed to serve the request.";
                readonly content: {
                    readonly 'application/json': {
                        readonly schema: {
                            readonly $ref: "#/components/schemas/Error";
                        };
                    };
                };
            };
        };
        readonly schemas: {
            readonly GeminiGenerateRequest: {
                readonly type: "object";
                readonly required: readonly ["contents"];
                readonly properties: {
                    readonly contents: {
                        readonly type: "array";
                        readonly minItems: 1;
                        readonly items: {
                            readonly type: "object";
                            readonly properties: {
                                readonly role: {
                                    readonly type: "string";
                                    readonly enum: readonly ["user", "model"];
                                };
                                readonly parts: {
                                    readonly type: "array";
                                    readonly items: {
                                        readonly type: "object";
                                        readonly description: "A text, inlineData, functionCall, or functionResponse part.";
                                    };
                                };
                            };
                        };
                    };
                    readonly systemInstruction: {
                        readonly type: "object";
                    };
                    readonly tools: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                        };
                    };
                    readonly toolConfig: {
                        readonly type: "object";
                    };
                    readonly generationConfig: {
                        readonly type: "object";
                        readonly properties: {
                            readonly temperature: {
                                readonly type: "number";
                            };
                            readonly topP: {
                                readonly type: "number";
                            };
                            readonly topK: {
                                readonly type: "integer";
                            };
                            readonly maxOutputTokens: {
                                readonly type: "integer";
                            };
                            readonly stopSequences: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly responseMimeType: {
                                readonly type: "string";
                            };
                            readonly responseSchema: {
                                readonly type: "object";
                            };
                            readonly thinkingConfig: {
                                readonly type: "object";
                            };
                        };
                    };
                };
            };
            readonly ChatCompletionRequest: {
                readonly type: "object";
                readonly required: readonly ["messages"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly description: "Model id, or 'auto' for automatic routing.";
                        readonly default: "auto";
                    };
                    readonly messages: {
                        readonly type: "array";
                        readonly minItems: 1;
                        readonly items: {
                            readonly $ref: "#/components/schemas/Message";
                        };
                    };
                    readonly temperature: {
                        readonly type: "number";
                        readonly minimum: 0;
                        readonly maximum: 2;
                    };
                    readonly max_tokens: {
                        readonly type: "integer";
                        readonly description: "Values <= 0 are treated as \"no limit\".";
                    };
                    readonly top_p: {
                        readonly type: "number";
                        readonly minimum: 0;
                        readonly maximum: 1;
                    };
                    readonly stop: {
                        readonly description: "Up to a few stop sequences.";
                        readonly oneOf: readonly [{
                            readonly type: "string";
                        }, {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "string";
                            };
                        }];
                    };
                    readonly stream: {
                        readonly type: "boolean";
                        readonly default: false;
                    };
                    readonly tools: {
                        readonly type: "array";
                        readonly items: {
                            readonly $ref: "#/components/schemas/Tool";
                        };
                        readonly nullable: true;
                    };
                    readonly tool_choice: {
                        readonly nullable: true;
                        readonly oneOf: readonly [{
                            readonly type: "string";
                            readonly enum: readonly ["none", "auto", "required", "any"];
                        }, {
                            readonly $ref: "#/components/schemas/ToolChoiceObject";
                        }];
                    };
                    readonly parallel_tool_calls: {
                        readonly type: "boolean";
                        readonly nullable: true;
                    };
                };
            };
            readonly Message: {
                readonly type: "object";
                readonly required: readonly ["role"];
                readonly properties: {
                    readonly role: {
                        readonly type: "string";
                        readonly enum: readonly ["system", "developer", "user", "assistant", "tool", "function"];
                    };
                    readonly content: {
                        readonly description: "A string, or an array of content parts (text and image_url) for vision.";
                        readonly oneOf: readonly [{
                            readonly type: "string";
                        }, {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                            };
                        }];
                        readonly nullable: true;
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                    readonly tool_calls: {
                        readonly type: "array";
                        readonly items: {
                            readonly $ref: "#/components/schemas/ToolCall";
                        };
                    };
                    readonly tool_call_id: {
                        readonly type: "string";
                    };
                };
            };
            readonly Tool: {
                readonly type: "object";
                readonly required: readonly ["type", "function"];
                readonly properties: {
                    readonly type: {
                        readonly type: "string";
                        readonly enum: readonly ["function"];
                    };
                    readonly function: {
                        readonly type: "object";
                        readonly required: readonly ["name"];
                        readonly properties: {
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly parameters: {
                                readonly type: "object";
                                readonly description: "JSON Schema for the function arguments.";
                            };
                            readonly strict: {
                                readonly type: "boolean";
                            };
                        };
                    };
                };
            };
            readonly ToolChoiceObject: {
                readonly type: "object";
                readonly required: readonly ["type", "function"];
                readonly properties: {
                    readonly type: {
                        readonly type: "string";
                        readonly enum: readonly ["function"];
                    };
                    readonly function: {
                        readonly type: "object";
                        readonly required: readonly ["name"];
                        readonly properties: {
                            readonly name: {
                                readonly type: "string";
                            };
                        };
                    };
                };
            };
            readonly ToolCall: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly type: {
                        readonly type: "string";
                        readonly enum: readonly ["function"];
                    };
                    readonly function: {
                        readonly type: "object";
                        readonly properties: {
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly arguments: {
                                readonly type: "string";
                                readonly description: "JSON-encoded arguments.";
                            };
                        };
                    };
                };
            };
            readonly ChatCompletionResponse: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly object: {
                        readonly type: "string";
                        readonly example: "chat.completion";
                    };
                    readonly created: {
                        readonly type: "integer";
                    };
                    readonly model: {
                        readonly type: "string";
                    };
                    readonly choices: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                            readonly properties: {
                                readonly index: {
                                    readonly type: "integer";
                                };
                                readonly message: {
                                    readonly $ref: "#/components/schemas/Message";
                                };
                                readonly finish_reason: {
                                    readonly type: "string";
                                    readonly nullable: true;
                                };
                            };
                        };
                    };
                    readonly usage: {
                        readonly $ref: "#/components/schemas/Usage";
                    };
                };
            };
            readonly CompletionRequest: {
                readonly type: "object";
                readonly required: readonly ["prompt"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly default: "auto";
                    };
                    readonly prompt: {
                        readonly type: "string";
                    };
                    readonly suffix: {
                        readonly type: "string";
                        readonly description: "Text after the cursor, for fill-in-the-middle clients.";
                    };
                    readonly temperature: {
                        readonly type: "number";
                        readonly minimum: 0;
                        readonly maximum: 2;
                    };
                    readonly max_tokens: {
                        readonly type: "integer";
                    };
                    readonly top_p: {
                        readonly type: "number";
                        readonly minimum: 0;
                        readonly maximum: 1;
                    };
                    readonly stop: {
                        readonly oneOf: readonly [{
                            readonly type: "string";
                        }, {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "string";
                            };
                        }];
                    };
                    readonly stream: {
                        readonly type: "boolean";
                        readonly default: false;
                    };
                };
            };
            readonly CompletionResponse: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly object: {
                        readonly type: "string";
                        readonly example: "text_completion";
                    };
                    readonly created: {
                        readonly type: "integer";
                    };
                    readonly model: {
                        readonly type: "string";
                    };
                    readonly choices: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                            readonly properties: {
                                readonly text: {
                                    readonly type: "string";
                                };
                                readonly index: {
                                    readonly type: "integer";
                                };
                                readonly logprobs: {
                                    readonly nullable: true;
                                };
                                readonly finish_reason: {
                                    readonly type: "string";
                                    readonly nullable: true;
                                };
                            };
                        };
                    };
                };
            };
            readonly EmbeddingRequest: {
                readonly type: "object";
                readonly required: readonly ["input"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly default: "auto";
                    };
                    readonly input: {
                        readonly oneOf: readonly [{
                            readonly type: "string";
                        }, {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "string";
                            };
                        }];
                    };
                    readonly dimensions: {
                        readonly type: "integer";
                        readonly minimum: 1;
                        readonly description: "Requested output dimensionality, if the model supports it.";
                    };
                };
            };
            readonly EmbeddingResponse: {
                readonly type: "object";
                readonly properties: {
                    readonly object: {
                        readonly type: "string";
                        readonly enum: readonly ["list"];
                    };
                    readonly data: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                            readonly properties: {
                                readonly object: {
                                    readonly type: "string";
                                    readonly enum: readonly ["embedding"];
                                };
                                readonly index: {
                                    readonly type: "integer";
                                };
                                readonly embedding: {
                                    readonly type: "array";
                                    readonly items: {
                                        readonly type: "number";
                                    };
                                };
                            };
                        };
                    };
                    readonly model: {
                        readonly type: "string";
                    };
                    readonly provider: {
                        readonly type: "string";
                    };
                    readonly usage: {
                        readonly $ref: "#/components/schemas/Usage";
                    };
                };
            };
            readonly ImageRequest: {
                readonly type: "object";
                readonly required: readonly ["prompt"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly default: "auto";
                    };
                    readonly prompt: {
                        readonly type: "string";
                        readonly minLength: 1;
                    };
                    readonly n: {
                        readonly type: "integer";
                        readonly minimum: 1;
                        readonly maximum: 4;
                    };
                    readonly size: {
                        readonly type: "string";
                        readonly example: "1024x1024";
                    };
                    readonly response_format: {
                        readonly type: "string";
                        readonly enum: readonly ["url", "b64_json"];
                    };
                };
            };
            readonly ImageResponse: {
                readonly type: "object";
                readonly properties: {
                    readonly created: {
                        readonly type: "integer";
                    };
                    readonly data: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                            readonly properties: {
                                readonly url: {
                                    readonly type: "string";
                                };
                                readonly b64_json: {
                                    readonly type: "string";
                                };
                            };
                        };
                    };
                    readonly model: {
                        readonly type: "string";
                    };
                    readonly provider: {
                        readonly type: "string";
                    };
                };
            };
            readonly VideoRequest: {
                readonly type: "object";
                readonly required: readonly ["prompt"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly default: "auto";
                    };
                    readonly prompt: {
                        readonly type: "string";
                        readonly minLength: 1;
                    };
                    readonly duration: {
                        readonly type: "integer";
                        readonly minimum: 1;
                        readonly maximum: 120;
                        readonly description: "Requested duration in seconds. Supported values are model-specific; nova-reel accepts multiples of 6.";
                    };
                    readonly aspect_ratio: {
                        readonly type: "string";
                        readonly enum: readonly ["16:9", "9:16"];
                    };
                    readonly image: {
                        readonly type: "string";
                        readonly format: "uri";
                        readonly description: "Optional starting-frame image URL.";
                    };
                    readonly seed: {
                        readonly type: "integer";
                        readonly minimum: -1;
                        readonly maximum: 2147483647;
                    };
                    readonly audio: {
                        readonly type: "boolean";
                        readonly description: "Request generated audio when the selected model supports it.";
                    };
                };
            };
            readonly SpeechRequest: {
                readonly type: "object";
                readonly required: readonly ["input"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly default: "auto";
                    };
                    readonly input: {
                        readonly type: "string";
                        readonly minLength: 1;
                    };
                    readonly voice: {
                        readonly type: "string";
                        readonly description: "OpenAI voice names are translated to the selected provider voice. Native Gemini and SiliconFlow names are also accepted; unknown names use the provider default.";
                    };
                    readonly response_format: {
                        readonly type: "string";
                        readonly example: "mp3";
                    };
                };
            };
            readonly TranscriptionRequest: {
                readonly type: "object";
                readonly required: readonly ["file", "model"];
                readonly properties: {
                    readonly file: {
                        readonly type: "string";
                        readonly format: "binary";
                        readonly description: "The audio file to transcribe (max 25 MB).";
                    };
                    readonly model: {
                        readonly type: "string";
                        readonly description: "'whisper-1' or 'auto' lets the router pick; a provider model id (e.g. 'whisper-large-v3-turbo', '@cf/openai/whisper') pins to that deployment.";
                    };
                    readonly language: {
                        readonly type: "string";
                        readonly description: "ISO-639-1 hint forwarded to the provider.";
                    };
                    readonly prompt: {
                        readonly type: "string";
                        readonly description: "Optional context/spelling hint forwarded to the provider.";
                    };
                    readonly temperature: {
                        readonly type: "number";
                        readonly minimum: 0;
                        readonly maximum: 1;
                    };
                    readonly response_format: {
                        readonly type: "string";
                        readonly enum: readonly ["json", "text", "verbose_json", "vtt"];
                        readonly default: "json";
                        readonly description: string;
                    };
                };
            };
            readonly ResponseRequest: {
                readonly type: "object";
                readonly required: readonly ["input"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly default: "auto";
                    };
                    readonly instructions: {
                        readonly type: "string";
                        readonly nullable: true;
                        readonly description: "System-level guidance, sent as a system message.";
                    };
                    readonly input: {
                        readonly description: "A string, or an array of Responses input items.";
                        readonly oneOf: readonly [{
                            readonly type: "string";
                        }, {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                            };
                        }];
                    };
                    readonly stream: {
                        readonly type: "boolean";
                        readonly default: false;
                    };
                    readonly max_output_tokens: {
                        readonly type: "integer";
                        readonly minimum: 1;
                        readonly nullable: true;
                    };
                    readonly tools: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                        };
                    };
                };
            };
            readonly ResponseObject: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly object: {
                        readonly type: "string";
                        readonly example: "response";
                    };
                    readonly created_at: {
                        readonly type: "integer";
                    };
                    readonly model: {
                        readonly type: "string";
                    };
                    readonly status: {
                        readonly type: "string";
                        readonly example: "completed";
                    };
                    readonly output: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                        };
                    };
                    readonly output_text: {
                        readonly type: "string";
                    };
                    readonly usage: {
                        readonly type: "object";
                    };
                };
            };
            readonly AnthropicMessageRequest: {
                readonly type: "object";
                readonly required: readonly ["messages"];
                readonly properties: {
                    readonly model: {
                        readonly type: "string";
                        readonly description: "Anthropic model name; mapped to your free pool. Defaults to `auto`.";
                    };
                    readonly max_tokens: {
                        readonly type: "integer";
                        readonly description: "Anthropic-required; non-positive values fall back to a default.";
                    };
                    readonly messages: {
                        readonly type: "array";
                        readonly minItems: 1;
                        readonly items: {
                            readonly type: "object";
                            readonly required: readonly ["role", "content"];
                            readonly properties: {
                                readonly role: {
                                    readonly type: "string";
                                    readonly enum: readonly ["user", "assistant", "system"];
                                };
                                readonly content: {
                                    readonly oneOf: readonly [{
                                        readonly type: "string";
                                    }, {
                                        readonly type: "array";
                                        readonly items: {
                                            readonly type: "object";
                                        };
                                    }];
                                };
                            };
                        };
                    };
                    readonly system: {
                        readonly description: "System prompt, as a string or an array of content blocks.";
                        readonly oneOf: readonly [{
                            readonly type: "string";
                        }, {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                            };
                        }];
                    };
                    readonly temperature: {
                        readonly type: "number";
                        readonly minimum: 0;
                        readonly maximum: 2;
                    };
                    readonly top_p: {
                        readonly type: "number";
                        readonly minimum: 0;
                        readonly maximum: 1;
                    };
                    readonly stream: {
                        readonly type: "boolean";
                        readonly default: false;
                    };
                    readonly stop_sequences: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                    readonly tools: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                            readonly required: readonly ["name"];
                            readonly properties: {
                                readonly name: {
                                    readonly type: "string";
                                };
                                readonly description: {
                                    readonly type: "string";
                                };
                                readonly input_schema: {
                                    readonly type: "object";
                                };
                            };
                        };
                    };
                    readonly tool_choice: {
                        readonly type: "object";
                        readonly properties: {
                            readonly type: {
                                readonly type: "string";
                                readonly enum: readonly ["auto", "any", "tool", "none"];
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                        };
                    };
                };
            };
            readonly AnthropicMessageResponse: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly type: {
                        readonly type: "string";
                        readonly enum: readonly ["message"];
                    };
                    readonly role: {
                        readonly type: "string";
                        readonly enum: readonly ["assistant"];
                    };
                    readonly model: {
                        readonly type: "string";
                    };
                    readonly content: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "object";
                        };
                    };
                    readonly stop_reason: {
                        readonly type: "string";
                        readonly nullable: true;
                        readonly enum: readonly ["end_turn", "max_tokens", "stop_sequence", "tool_use"];
                    };
                    readonly stop_sequence: {
                        readonly type: "string";
                        readonly nullable: true;
                    };
                    readonly usage: {
                        readonly type: "object";
                        readonly properties: {
                            readonly input_tokens: {
                                readonly type: "integer";
                            };
                            readonly output_tokens: {
                                readonly type: "integer";
                            };
                        };
                    };
                };
            };
            readonly CountTokensResponse: {
                readonly type: "object";
                readonly properties: {
                    readonly input_tokens: {
                        readonly type: "integer";
                    };
                };
            };
            readonly Usage: {
                readonly type: "object";
                readonly properties: {
                    readonly prompt_tokens: {
                        readonly type: "integer";
                    };
                    readonly completion_tokens: {
                        readonly type: "integer";
                    };
                    readonly total_tokens: {
                        readonly type: "integer";
                    };
                };
            };
            readonly ModelList: {
                readonly type: "object";
                readonly properties: {
                    readonly object: {
                        readonly type: "string";
                        readonly enum: readonly ["list"];
                    };
                    readonly data: {
                        readonly type: "array";
                        readonly items: {
                            readonly $ref: "#/components/schemas/Model";
                        };
                    };
                };
            };
            readonly Model: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly object: {
                        readonly type: "string";
                        readonly enum: readonly ["model"];
                    };
                    readonly created: {
                        readonly type: "integer";
                    };
                    readonly owned_by: {
                        readonly type: "string";
                    };
                };
            };
            readonly Error: {
                readonly type: "object";
                readonly properties: {
                    readonly error: {
                        readonly type: "object";
                        readonly properties: {
                            readonly message: {
                                readonly type: "string";
                            };
                            readonly type: {
                                readonly type: "string";
                            };
                            readonly param: {
                                readonly type: "string";
                                readonly nullable: true;
                            };
                            readonly code: {
                                readonly type: "string";
                                readonly nullable: true;
                            };
                        };
                    };
                };
            };
        };
    };
};
export type OpenApiSpec = typeof openapiSpec;
//# sourceMappingURL=openapi.d.ts.map