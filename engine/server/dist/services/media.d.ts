/** Platforms with a media adapter below. catalog-sync gates media rows on this
 *  (decoupled from the chat provider registry — e.g. SiliconFlow is media-only). */
export declare const MEDIA_PLATFORMS: Set<string>;
/** Video uses a dedicated optional catalog registry so binaries that predate
 *  this modality ignore the rows instead of accidentally ingesting them as
 *  chat models. Keep its adapter allowlist separate for the same reason. */
export declare const VIDEO_PLATFORMS: Set<string>;
/** Platforms with a speech-to-text adapter below. catalog-sync gates the
 *  catalog's `transcriptionModels` entries on this, the way MEDIA_PLATFORMS
 *  gates the generative-media rows. */
export declare const TRANSCRIPTION_PLATFORMS: Set<string>;
export type MediaModality = 'image' | 'video' | 'audio' | 'transcription';
export interface MediaModelRow {
    id: number;
    platform: string;
    model_id: string;
    display_name: string;
    modality: MediaModality;
    priority: number;
    enabled: number;
    quota_label: string;
    key_id: number | null;
    meta_json: string | null;
}
export declare class MediaError extends Error {
    status: number;
    /** Optional machine-readable error code surfaced in the OpenAI-shaped body. */
    code?: string;
    /** Back-off the upstream provider stated (`Retry-After` header), in
     *  milliseconds — relayed to the client so an SDK sleeps the stated amount
     *  instead of hammering the chain, mirroring the embeddings path. */
    retryAfterMs?: number;
    constructor(message: string, status: number, code?: string, retryAfterMs?: number);
}
export interface ImageResult {
    platform: string;
    modelId: string;
    images: Array<{
        b64_json?: string;
        url?: string;
    }>;
}
export interface SpeechResult {
    platform: string;
    modelId: string;
    audio: Buffer;
    contentType: string;
}
export interface VideoResult {
    platform: string;
    modelId: string;
    video: Buffer;
    contentType: string;
}
export interface ImageParams {
    prompt: string;
    n?: number;
    size?: string;
    image?: string;
}
export interface SpeechParams {
    input: string;
    voice?: string;
    format?: string;
}
export interface VideoParams {
    prompt: string;
    duration?: number;
    aspectRatio?: '16:9' | '9:16';
    image?: string;
    seed?: number;
    audio?: boolean;
}
export declare function listMediaModels(modality: MediaModality): MediaModelRow[];
/** All media models (both modalities, including disabled) for the dashboard. */
export declare function listAllMediaModels(): MediaModelRow[];
/** Generate image(s), failing over across providers serving the modality.
 *  When params.image is set this is an edit, not a generation: only the
 *  google image rows can take a source image, so the chain is restricted to
 *  them (other providers would silently ignore the input). */
export declare function runImageGeneration(model: string | undefined, params: ImageParams): Promise<ImageResult>;
/** Generate a video, failing over across catalogued text-to-video providers.
 *  `clientSignal` is the API caller's connection: when it aborts, the in-flight
 *  upstream request is dropped and no further provider is tried. */
export declare function runVideoGeneration(model: string | undefined, params: VideoParams, clientSignal?: AbortSignal): Promise<VideoResult>;
/** Per-model adapter metadata carried on the catalog entry (meta_json). */
export interface TranscriptionMeta {
    /** Subtitle formats the provider returns natively (e.g. ['vtt']). Formats
     *  not produced natively by the chain are refused with 400 at the route. */
    subtitleFormats?: string[];
    /** Provider upload ceiling in bytes; absent = MAX_TRANSCRIPTION_BYTES. */
    maxBytes?: number | null;
    /** Adapter request flavor where one platform hosts more than one deployment
     *  style. Cloudflare: 'json' = JSON body with base64 audio (large-v3-turbo),
     *  'binary' = raw bytes (plain whisper, the default). */
    requestStyle?: string | null;
}
/** Global upload ceiling enforced by the route (multer) so it can reject
 *  early with a clean OpenAI-shaped 413 instead of buffering an upload no
 *  provider can accept. Per-model catalog `maxBytes` may only lower this. */
export declare const MAX_TRANSCRIPTION_BYTES: number;
export interface TranscriptionParams {
    file: Buffer;
    filename: string;
    mimeType?: string;
    language?: string;
    prompt?: string;
    temperature?: number;
    /** 'json' | 'text' | 'verbose_json' | 'vtt' (srt is rejected at the route). */
    responseFormat: string;
}
export interface TranscriptionResult {
    platform: string;
    modelId: string;
    text: string;
    language?: string;
    duration?: number;
    segments?: unknown[];
    vtt?: string;
}
/** Transcribe audio, failing over across STT providers. 429s bench the
 *  (platform, model, key) triple through the standard cooldown machinery so a
 *  rate-limited key is skipped on subsequent requests, exactly like chat. */
export declare function runTranscription(model: string | undefined, p: TranscriptionParams): Promise<TranscriptionResult>;
/** Synthesize speech, failing over across providers serving the modality. */
export declare function runSpeech(model: string | undefined, params: SpeechParams): Promise<SpeechResult>;
//# sourceMappingURL=media.d.ts.map