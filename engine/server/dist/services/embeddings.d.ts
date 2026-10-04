import type { Db } from '../db/types.js';
export interface EmbeddingModelRow {
    id: number;
    family: string;
    platform: string;
    model_id: string;
    display_name: string;
    dimensions: number;
    max_input_tokens: number | null;
    priority: number;
    enabled: number;
    quota_label: string;
    key_id: number | null;
}
export interface EmbeddingsResult {
    family: string;
    platform: string;
    modelId: string;
    dimensions: number;
    vectors: number[][];
    inputTokens: number;
}
export declare class EmbeddingsError extends Error {
    status: number;
    code?: string;
    /** Back-off the upstream provider stated (`Retry-After` header or a
     *  retry-delay field in the error body), in milliseconds. Kept separate from
     *  the message so the route can answer the client with a real Retry-After
     *  instead of a bare 429, the same way the chat router benches keys. */
    retryAfterMs?: number;
    constructor(message: string, status: number, code?: string, retryAfterMs?: number);
}
export declare function listEmbeddingModels(): EmbeddingModelRow[];
export declare function getDefaultFamily(): string;
/** Map the request's `model` to a family: 'auto'/empty → default; a family
 * name → itself; a provider-specific model id → its family. */
export declare function resolveFamily(model: string | undefined): string | null;
/** Provider adapters that can safely receive catalog-managed embedding rows. */
export declare const EMBEDDING_PLATFORMS: Set<string>;
export declare function probeEmbeddingDimensions(baseUrl: string, key: string, modelId: string): Promise<number>;
export interface CustomEmbeddingRegistration {
    keyId: number;
    modelId: string;
    displayName: string | null;
    family: string;
    dimensions: number;
    maxInputTokens: number | null;
    quotaLabel: string;
}
/**
 * Upsert one custom embedding model bound to an endpoint credential — the
 * shared write path behind POST /api/embeddings/custom and the bulk key
 * importer (#382). Throws EmbeddingsError(400) when the family already exists
 * at a different dimension: vectors from mismatched spaces must never mix, so
 * the caller has to pick a new family name instead.
 */
export declare function registerCustomEmbeddingModel(db: Db, reg: CustomEmbeddingRegistration): {
    modelDbId: number;
    created: boolean;
};
/** Embed `inputs` via the family's provider chain, failing over within the
 * family on any provider error. Throws EmbeddingsError when the chain is dry.
 *
 * `dimensions` (optional): client-supplied output-dimension override forwarded to
 * providers that support MRL truncation (NVIDIA NeMo NIM, Google Gemini Embedding,
 * OpenAI text-embedding-3-*). Providers that ignore the field see an identical
 * request body. The override is independent of the model's native dimension — the
 * family registry still pins the canonical dimension, this just lets callers ask
 * for a smaller vector at the cost of some accuracy. */
export declare function runEmbeddings(model: string | undefined, inputs: string[], dimensions?: number): Promise<EmbeddingsResult>;
/** Whole seconds the client should wait before retrying an embeddings request:
 *  the soonest upstream back-off when the whole chain was rate limited, else the
 *  monthly-budget reset for a local quota block. Undefined means the caller
 *  shouldn't set the header. */
export declare function embeddingsRetryAfterSec(err: EmbeddingsError): number | undefined;
//# sourceMappingURL=embeddings.d.ts.map