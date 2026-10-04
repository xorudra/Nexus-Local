import { OpenAICompatProvider } from '../providers/openai-compat.js';
/** Hard cap on the catalog body we will read. The largest real OpenAI-style
 *  catalog (OpenRouter, ~400 models with metadata) is well under 1 MB. */
export declare const MAX_CATALOG_BYTES: number;
/** Hard cap on how many ids we hand back — a checkbox list, not a data dump. */
export declare const MAX_DISCOVERED_MODELS = 500;
/** What a discovered model IS, when it discernibly isn't a chat model (#1051).
 *  Absent means "chat as far as anyone can tell" — the field is emitted only
 *  when a non-chat kind is detected, so plain chat rows keep their shape. */
export type DiscoveredModelKind = 'embedding' | 'image' | 'audio' | 'transcription' | 'video';
export interface DiscoveredModel {
    id: string;
    ownedBy: string | null;
    /** Approximate context window in tokens when the upstream advertises one
     *  (OpenRouter's context_length, Ollama's ctx_len, max_model_len, ...). */
    contextWindow?: number;
    /** Human-readable price hint ("free", "$1.25/M in $2/M out") when the
     *  upstream ships one — normalized to USD per MILLION tokens (#685). */
    priceNote?: string;
    /** True when every price component the upstream advertises is zero, or it
     *  plainly says "free". Set only alongside priceNote, and the only thing the
     *  picker badges green — the note itself is never pattern-matched. */
    isFree?: boolean;
    /** True when the upstream advertises image input (modalities/vision). */
    vision?: boolean;
    /** Present only when the model is discernibly NOT a chat model (#1051). */
    kind?: DiscoveredModelKind;
}
/** Carries the HTTP status the route should answer with, so a relay's 401 stays
 *  a 401 and an unreachable box reads as a gateway problem. */
export declare class ModelDiscoveryError extends Error {
    readonly status: number;
    constructor(status: number, message: string);
}
/** The model's kind read off its id, for upstreams that advertise no usable
 *  type metadata (#1051). Returns a kind or undefined and never 'chat': absence
 *  of a marker is not evidence of anything, and chat stays the default. */
export declare function classifyModelId(id: string): DiscoveredModelKind | undefined;
/** Whether this payload carries a model list at all — the difference between
 *  an endpoint that genuinely serves nothing and one whose answer we can't
 *  read (an HTML error page, a login redirect, a bare error object). */
export declare function hasModelList(payload: unknown): boolean;
/**
 * Model ids out of any /models envelope we recognize, deduped, sorted and
 * capped. Returns an empty list for a payload with no list in it — the caller
 * decides whether that's an error worth surfacing.
 */
export declare function parseModelCatalog(payload: unknown): DiscoveredModel[];
/**
 * Read a response body with a hard byte cap. A declared Content-Length over the
 * cap is refused without reading anything; otherwise the stream is abandoned
 * the moment it runs past the cap, so a base_url pointed at something that
 * never stops can't take the process with it.
 */
export declare function readCappedBody(res: Response, maxBytes?: number): Promise<string>;
/**
 * Ask a custom OpenAI-compatible endpoint what it serves. Reuses the provider
 * adapter's own catalog fetch (auth header, proxy, timeout, quota bookkeeping)
 * rather than re-implementing an HTTP call here.
 */
export declare function discoverEndpointModels(baseUrl: string, apiKey: string): Promise<DiscoveredModel[]>;
/**
 * The shared half of discovery: GET `${provider}/models` through the adapter
 * and parse whatever envelope comes back. Built-in OpenAI-compatible platforms
 * (#1348) call this with their REGISTERED adapter, so the registry's base URL,
 * extra headers (User-Agent quirks) and auth scheme apply exactly as they do
 * for health checks. `label` only names the endpoint in error messages.
 */
export declare function discoverProviderModels(provider: OpenAICompatProvider, apiKey: string, label: string): Promise<DiscoveredModel[]>;
/** Output cap on the probe request. Exported so the test can assert the floor
 *  rather than a magic number. See the call site for why it is not 1. */
export declare const PROBE_MAX_TOKENS = 4;
/** Result of a capability probe (#874, phase 1). The `ping` latency/sample
 *  fields are unchanged from the original probe; `reasoning` and `toolCalls`
 *  are OPTIONAL additions so a client reading only `{ modelId, latencyMs }`
 *  keeps working (backward compatible). A probe that answers `ping` but then
 *  errors on a capability probe leaves that capability undefined — the caller
 *  only writes `supports_tools` when `toolCalls === true`. */
export interface ProbeCapabilities {
    /** True when the reasoning probe's answer contained the expected token;
     *  false when it answered something else; undefined when the probe errored
     *  or timed out (unknown). */
    reasoning?: boolean;
    /** True when the tool probe returned `finish_reason: 'tool_calls'`; false
     *  when it finished some other way; undefined when the probe errored or
     *  timed out (unknown). */
    toolCalls?: boolean;
}
export interface ProbeEndpointModelResult extends ProbeCapabilities {
    modelId: string;
    latencyMs: number;
    inputTokens: number;
    outputTokens: number;
}
/**
 * Fire one minimal real chat request at a custom endpoint to measure latency
 * and confirm the key works end-to-end ("probe now", #685 follow-up). When the
 * caller already knows which model to probe (a model registered on this
 * endpoint — the one whose bandit stats the sample feeds), it passes
 * `preferredModelId` and the discovery round-trip is skipped entirely; only an
 * endpoint with nothing registered falls back to discovering a model id.
 *
 * Phase 1 (#874): after the `ping` latency probe succeeds, two extra probes
 * fire while the operator is still watching — a deterministic reasoning probe
 * and a tool-call probe. These are best-effort: a capability probe that errors
 * or times out simply leaves that capability flag unset, so a flaky relay can
 * still clear a cooldown and record a success sample from the `ping`. Only a
 * capability probe that returns positive evidence sets its flag.
 *
 * Returns the probed model id, the round-trip latency and the token counts so
 * the caller can write a stats row; throws ModelDiscoveryError with a clean
 * message on any failure (the caller must NOT record a sample then).
 */
export declare function probeEndpointModel(baseUrl: string, apiKey: string, preferredModelId?: string | null): Promise<ProbeEndpointModelResult>;
/**
 * Run the reasoning and tool-call capability probes against a model (#874,
 * phase 1). Best-effort: a probe that errors leaves its flag unset rather than
 * throwing — the caller treats "unset" as "unknown" and only writes
 * `supports_tools` on a positive `toolCalls`.
 *
 * Exposed separately so a future caller can run capability probes without the
 * ping (or reuse the probe set under a different transport). The current probe
 * chain calls this from `probeEndpointModel`.
 */
export declare function probeModelCapabilities(provider: OpenAICompatProvider, apiKey: string, modelId: string): Promise<ProbeCapabilities>;
//# sourceMappingURL=model-discovery.d.ts.map