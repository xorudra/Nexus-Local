import { BaseProvider, providerHttpError } from './base.js';
import { contentToString } from '../lib/content.js';
import { proxyFetch } from '../lib/proxy.js';
import { recordQuotaObservationsFromResponse } from '../services/provider-quota.js';
import { providerTimeoutMs, streamStallTimeoutMs } from '../lib/provider-timeout.js';
import { sanitizeForGemini } from '../lib/gemini-wire.js';
import { resolveMaxTokens } from '../lib/sampling-params.js';
export { sanitizeForGemini } from '../lib/gemini-wire.js';
const API_BASE = 'https://generativelanguage.googleapis.com/v1beta';
function googleHttpError(res, body) {
    const err = providerHttpError(res, `Google API error ${res.status}: ${body?.error?.message ?? res.statusText}`, body);
    // Gemini's human-readable message can omit the quota window. Keep only the
    // daily signal from QuotaFailure, not the complete upstream payload (#1339).
    const details = body?.error?.details;
    if (res.status === 429 && Array.isArray(details)) {
        err.dailyQuotaExhausted = details.some(detail => detail?.['@type'] === 'type.googleapis.com/google.rpc.QuotaFailure'
            && Array.isArray(detail.violations)
            && detail.violations.some((violation) => typeof violation?.quotaId === 'string' && /PerDay/.test(violation.quotaId)));
    }
    return err;
}
// Gemini 3 REQUIRES the `thoughtSignature` that accompanied a function call to
// be echoed back whenever that call appears in conversation history, or it
// rejects the request with 400 "Function call is missing a thought_sig". But
// OpenAI-format clients (the API surface we expose) have no standard field to
// carry a provider-specific signature, so it can be dropped on the round-trip
// and multi-turn tool conversations through Gemini fail. Cache each signature
// we emit keyed by the tool-call id and by a stable name/arguments fingerprint;
// the latter keeps the Anthropic bridge resilient when an agent/client rewrites
// opaque tool ids. Strictly additive: a cache miss yields exactly the previous
// behavior (the request may 400 and fail over, as before). Bounded with a TTL so
// it can't grow unbounded.
const THOUGHT_SIG_TTL_MS = 30 * 60 * 1000; // 30 min — longer than any single tool loop
const THOUGHT_SIG_MAX = 5000;
const thoughtSigCache = new Map();
function canonicalThoughtSigArgs(args) {
    if (typeof args === 'string') {
        try {
            return JSON.stringify(JSON.parse(args));
        }
        catch {
            return args;
        }
    }
    return JSON.stringify(args ?? {});
}
function thoughtSigCallKey(name, args) {
    if (!name)
        return undefined;
    return `call:${name}:${canonicalThoughtSigArgs(args)}`;
}
// Fallback for functionCall parts that have neither a client-preserved nor a
// cached signature (replayed history after a restart, TTL expiry, calls first
// produced by another provider). Gemini 3 strictly validates the field, but
// the signature is an encrypted blob the server checks — a fabricated value
// (e.g. a hash) is NOT accepted. Google documents exactly two sentinel
// strings for calls the API didn't produce; either tells the server to skip
// signature validation (at the cost of some reasoning quality), which is the
// official last resort for signature-less history.
const DUMMY_THOUGHT_SIGNATURE = 'context_engineering_is_the_way_to_go';
// The sentinel is a silent quality trade — Gemini stops validating and loses
// the reasoning thread for that call — so say so once per process. A steady
// stream of these means the cache is missing (restart loop, TTL too short, or
// history minted by another provider) rather than a one-off replay, and
// without a log there is nothing to correlate degraded tool-calling against.
let warnedDummyThoughtSig = false;
function noteDummyThoughtSignature(name) {
    if (warnedDummyThoughtSig)
        return;
    warnedDummyThoughtSig = true;
    console.warn(`[Google] no thought_signature for a replayed tool call (${name ?? 'unknown'}); ` +
        'falling back to the documented skip-validation sentinel — Gemini will not ' +
        'validate the signature for these turns, at some reasoning-quality cost. ' +
        '(Logged once per process.)');
}
function rememberThoughtSigKey(key, sig) {
    if (!key || !sig)
        return;
    // Cheap eviction: when full, drop the oldest insertion (Map preserves order).
    if (thoughtSigCache.size >= THOUGHT_SIG_MAX) {
        const oldest = thoughtSigCache.keys().next().value;
        if (oldest !== undefined)
            thoughtSigCache.delete(oldest);
    }
    thoughtSigCache.set(key, { sig, exp: Date.now() + THOUGHT_SIG_TTL_MS });
}
function rememberThoughtSig(callId, sig, name, args) {
    rememberThoughtSigKey(callId ? `id:${callId}` : undefined, sig);
    rememberThoughtSigKey(thoughtSigCallKey(name, args), sig);
}
function recallThoughtSigKey(key) {
    if (!key)
        return undefined;
    const hit = thoughtSigCache.get(key);
    if (!hit)
        return undefined;
    if (hit.exp < Date.now()) {
        thoughtSigCache.delete(key);
        return undefined;
    }
    return hit.sig;
}
function recallThoughtSig(callId, name, args) {
    return recallThoughtSigKey(callId ? `id:${callId}` : undefined)
        ?? recallThoughtSigKey(thoughtSigCallKey(name, args));
}
function isGemmaModel(modelId) {
    const normalized = modelId.toLowerCase().replace(/^models\//, '');
    return /(?:^|[/.:])gemma[-_]/.test(normalized);
}
function systemInstructionText(systemInstruction) {
    const text = systemInstruction?.parts
        ?.map(part => part.text ?? '')
        .join('\n\n')
        .trim();
    return text ? text : null;
}
// Gemma models on the Gemini API historically 400 with "Developer instruction
// is not enabled", so system prompts fold into the first user turn instead of
// riding systemInstruction (#500). Older Gemma 3.x still rejects system
// instructions and users can register those ids, so the fold stays. Tools and
// functionCall/functionResponse history are deliberately NOT touched here
// anymore: Gemma 4 supports native function calling, and stripping them made
// the dashboard supports_tools toggle a no-op (#582).
function contentsForModel(modelId, contents, systemInstruction) {
    if (!isGemmaModel(modelId))
        return { contents, systemInstruction };
    const systemText = systemInstructionText(systemInstruction);
    if (!systemText)
        return { contents };
    return {
        contents: [
            { role: 'user', parts: [{ text: systemText }] },
            ...contents,
        ],
    };
}
function safeParseObject(raw) {
    try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            return parsed;
        }
        return { value: parsed };
    }
    catch {
        return { value: raw };
    }
}
function normalizeGeminiArgs(args) {
    if (typeof args === 'string')
        return args;
    return JSON.stringify(args ?? {});
}
function toGeminiFinishReason(finishReason) {
    const r = (finishReason ?? '').toUpperCase();
    if (!r)
        return 'stop';
    if (r === 'MAX_TOKENS')
        return 'length';
    if (r === 'SAFETY' || r === 'RECITATION' || r === 'BLOCKLIST' || r === 'PROHIBITED_CONTENT' || r === 'SPII') {
        return 'content_filter';
    }
    return 'stop';
}
// Google Gemini accepts only a subset of JSON Schema (~OpenAPI 3.0).
// Strip fields that opencode / other strict-JSON-Schema clients send but
// Google rejects with 400 "Unknown name '<field>'".
// OpenAI clients can't express Gemini's native Google Search grounding, so we
// treat a tool named `google_search` (a few spellings) as the signal to enable
// it. It maps to Gemini's `{ google_search: {} }` tool rather than a function
// declaration, and can ride alongside real function tools in the same array. (#59)
const GROUNDING_TOOL_NAMES = new Set(['google_search', 'googlesearch', 'google_search_retrieval']);
// reasoning_effort → Gemini thinkingBudget (tokens). The low/medium/high
// budgets follow the common gateway convention (OpenRouter's effort mapping);
// 'none'/'minimal' disable thinking outright. Models that can't run at the
// requested budget 400 and fail over like any provider-invalid request.
const EFFORT_THINKING_BUDGET = {
    low: 1024,
    medium: 8192,
    high: 24576,
};
/**
 * Extended generationConfig knobs translated from the OpenAI wire: topK,
 * seed, penalties, and structured output. JSON output conflicts with function
 * calling on Gemini ("Function calling with a response mime type:
 * 'application/json' is unsupported"), so response_format is only applied on
 * tool-free requests. Params Gemini has no equivalent for (min_p, logit_bias,
 * logprobs…) are dropped by the platform policy in lib/sampling-params.ts and
 * are ignored here. Exported for tests.
 */
export function toGeminiExtendedConfig(options) {
    const out = {
        topK: options?.top_k,
        seed: options?.seed,
        presencePenalty: options?.presence_penalty,
        frequencyPenalty: options?.frequency_penalty,
    };
    const rf = options?.response_format;
    // Count only real function declarations, mirroring hasFunctionDeclarations:
    // grounding pseudo-tools (google_search etc.) are converted to a grounding
    // block by toGeminiTools and never conflict with responseMimeType — raw
    // tools.length was silently dropping structured output for grounding-only
    // requests.
    const hasTools = (options?.tools ?? []).some(t => !GROUNDING_TOOL_NAMES.has(t.function.name.toLowerCase()));
    if (rf && !hasTools) {
        out.responseMimeType = 'application/json';
        const schema = rf.type === 'json_schema' ? rf.json_schema?.schema : undefined;
        if (schema)
            out.responseSchema = sanitizeForGemini(schema);
    }
    // Request-side reasoning control: reasoning_effort → thinkingConfig. Only
    // set when the client asked — a request without the knob keeps Gemini's
    // model-default thinking behavior unchanged. includeThoughts surfaces
    // thought summaries so reasoning_content flows back out (see
    // extractReasoningContent).
    const effort = options?.reasoning_effort;
    if (effort) {
        out.thinkingConfig = (effort === 'none' || effort === 'minimal')
            ? { thinkingBudget: 0 }
            : { thinkingBudget: EFFORT_THINKING_BUDGET[effort], includeThoughts: true };
    }
    return out;
}
function toGeminiTools(tools) {
    if (!tools || tools.length === 0)
        return undefined;
    const functionDeclarations = [];
    let grounding = false;
    for (const t of tools) {
        if (GROUNDING_TOOL_NAMES.has(t.function.name.toLowerCase())) {
            grounding = true;
            continue;
        }
        functionDeclarations.push({
            name: t.function.name,
            description: t.function.description,
            parameters: sanitizeForGemini(t.function.parameters),
        });
    }
    const out = [];
    if (grounding)
        out.push({ google_search: {} });
    if (functionDeclarations.length > 0)
        out.push({ functionDeclarations });
    return out.length > 0 ? out : undefined;
}
function hasFunctionDeclarations(tools) {
    return tools?.some(t => 'functionDeclarations' in t) ?? false;
}
function toGeminiToolConfig(toolChoice) {
    if (!toolChoice)
        return undefined;
    if (typeof toolChoice === 'string') {
        const mode = toolChoice === 'none'
            ? 'NONE'
            : toolChoice === 'required'
                ? 'ANY'
                : 'AUTO';
        return { functionCallingConfig: { mode } };
    }
    return {
        functionCallingConfig: {
            mode: 'ANY',
            allowedFunctionNames: [toolChoice.function.name],
        },
    };
}
const MAX_IMAGE_BYTES = 8 * 1024 * 1024; // 8 MB cap on fetched/inlined images
const MAX_VIDEO_BYTES = 20 * 1024 * 1024; // 20 MB cap — Gemini inline video limit
// Videos bigger than the inline limit go through the Gemini Files API instead
// (upload once, reference with fileData). 200 MB keeps memory/time sane.
const MAX_VIDEO_FILEDATA_BYTES = 200 * 1024 * 1024;
// Pull the URL out of an OpenAI image content block. Accepts both the object
// form `{ image_url: { url } }` and the shorthand `{ image_url: '...' }`.
function extractImageUrl(block) {
    const iu = block?.image_url;
    if (typeof iu === 'string')
        return iu;
    if (iu && typeof iu.url === 'string')
        return iu.url;
    return undefined;
}
// Pull the URL out of an OpenAI-style media content block. Accepts both the
// object form `{ video_url: { url } }` and the shorthand `{ video_url: '...' }`.
function extractMediaUrl(block, key) {
    const v = block?.[key];
    if (typeof v === 'string')
        return v;
    if (v && typeof v.url === 'string')
        return v.url;
    return undefined;
}
// Convert a media URL to a Gemini inlineData part. Handles base64 `data:` URLs
// directly; for `http(s)` URLs we fetch and inline because the Gemini API does
// not fetch external URLs itself. Same SSRF posture as images: http/https
// only, size-capped, 30s timeout. Returns null (part skipped) on any failure.
async function mediaUrlToInlineData(url, maxBytes, defaultMime) {
    const dataMatch = /^data:([^;,]+)?(;base64)?,(.*)$/s.exec(url);
    if (dataMatch) {
        const mimeType = dataMatch[1] || 'application/octet-stream';
        const isBase64 = Boolean(dataMatch[2]);
        const payload = dataMatch[3] ?? '';
        const data = isBase64
            ? payload
            : Buffer.from(decodeURIComponent(payload)).toString('base64');
        if (Buffer.byteLength(data, 'base64') > maxBytes)
            return null;
        return { mimeType, data };
    }
    if (/^https?:\/\//i.test(url)) {
        try {
            const res = await proxyFetch(url, { signal: AbortSignal.timeout(30_000) }, 'google', 'video', 30_000);
            if (!res.ok)
                return null;
            const buf = Buffer.from(await res.arrayBuffer());
            if (buf.length === 0 || buf.length > maxBytes)
                return null;
            const mimeType = res.headers.get('content-type')?.split(';')[0]?.trim() || defaultMime;
            return { mimeType, data: buf.toString('base64') };
        }
        catch {
            return null;
        }
    }
    return null;
}
// Convert an image URL to a Gemini inlineData part. Handles base64 `data:` URLs
// directly; for `http(s)` URLs we fetch and inline because the Gemini API does
// not fetch external URLs itself. Fetching a user-supplied URL is a minor SSRF
// surface, acceptable for a single-user self-hosted proxy; we still restrict to
// http/https and cap the size. Returns null (part skipped) on any failure.
async function imageUrlToInlineData(url) {
    return mediaUrlToInlineData(url, MAX_IMAGE_BYTES, 'image/jpeg');
}
// Upload video bytes to the Gemini Files API (used for videos over the 20MB
// inlineData limit). Resumable upload via proxyFetch so it honors the egress
// proxy. Returns the file URI once the file is ACTIVE, or null on failure.
async function uploadVideoToFilesApi(apiKey, buf, mimeType) {
    try {
        // 1. Start a resumable upload session.
        const start = await proxyFetch('https://generativelanguage.googleapis.com/upload/v1beta/files', {
            method: 'POST',
            headers: {
                'x-goog-api-key': apiKey,
                'X-Goog-Upload-Protocol': 'resumable',
                'X-Goog-Upload-Command': 'start',
                'X-Goog-Upload-Header-Content-Length': String(buf.length),
                'X-Goog-Upload-Header-Content-Type': mimeType,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ file: { display_name: 'freellmapi-video' } }),
            signal: AbortSignal.timeout(30_000),
        }, 'google', 'video', 30_000);
        if (!start.ok)
            return null;
        const uploadUrl = start.headers.get('x-goog-upload-url');
        if (!uploadUrl)
            return null;
        // 2. Upload the bytes and finalize.
        const upload = await proxyFetch(uploadUrl, {
            method: 'POST',
            headers: {
                'X-Goog-Upload-Command': 'upload, finalize',
                'X-Goog-Upload-Offset': '0',
                'Content-Type': mimeType,
            },
            body: new Uint8Array(buf),
            signal: AbortSignal.timeout(120_000),
        }, 'google', 'video', 120_000);
        if (!upload.ok)
            return null;
        const created = (await upload.json().catch(() => null));
        let fileName = created?.file?.name;
        let fileUri = created?.file?.uri;
        let state = created?.file?.state;
        // 3. Poll until the file is ACTIVE (video needs server-side processing).
        const deadline = Date.now() + 90_000;
        while (state === 'PROCESSING' && fileName && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 2000));
            const check = await proxyFetch(`https://generativelanguage.googleapis.com/v1beta/${fileName}`, { headers: { 'x-goog-api-key': apiKey }, signal: AbortSignal.timeout(15_000) }, 'google', 'video', 15_000).catch(() => null);
            if (!check?.ok)
                break;
            const f = (await check.json().catch(() => null));
            fileName = f?.name ?? fileName;
            fileUri = f?.uri ?? fileUri;
            state = f?.state;
        }
        return state === 'ACTIVE' ? (fileUri ?? null) : null;
    }
    catch {
        return null;
    }
}
// Resolve a video URL to a Gemini part. Small videos (<=20MB) go inlineData;
// bigger ones (<=200MB) are uploaded via the Files API and referenced with
// fileData. data: URIs keep the old inline-only path. Returns null when the
// video can't be fetched or exceeds the cap (part is then skipped).
async function videoUrlToGeminiPart(url, apiKey) {
    if (/^data:/i.test(url)) {
        const inlineData = await mediaUrlToInlineData(url, MAX_VIDEO_BYTES, 'video/mp4');
        return inlineData ? { inlineData } : null;
    }
    if (!/^https?:\/\//i.test(url))
        return null;
    try {
        const res = await proxyFetch(url, { signal: AbortSignal.timeout(120_000) }, 'google', 'video', 120_000);
        if (!res.ok)
            return null;
        const buf = Buffer.from(await res.arrayBuffer());
        if (buf.length === 0 || buf.length > MAX_VIDEO_FILEDATA_BYTES)
            return null;
        const mimeType = res.headers.get('content-type')?.split(';')[0]?.trim() || 'video/mp4';
        if (buf.length <= MAX_VIDEO_BYTES) {
            return { inlineData: { mimeType, data: buf.toString('base64') } };
        }
        const fileUri = await uploadVideoToFilesApi(apiKey, buf, mimeType);
        return fileUri ? { fileData: { fileUri, mimeType } } : null;
    }
    catch {
        return null;
    }
}
// Build Gemini parts for a user message: joined text first, then any images
// and videos as inlineData. Non-array content (string/null) collapses to a
// single text part.
async function userContentToParts(content, apiKey) {
    const parts = [];
    const text = contentToString(content);
    if (text.length > 0)
        parts.push({ text });
    if (Array.isArray(content)) {
        for (const block of content) {
            const type = block?.type;
            if (type === 'video_url' || type === 'video') {
                const url = extractMediaUrl(block, 'video_url');
                if (!url)
                    continue;
                const part = await videoUrlToGeminiPart(url, apiKey);
                if (part)
                    parts.push(part);
                continue;
            }
            if (type !== 'image_url' && type !== 'image')
                continue;
            const url = extractImageUrl(block);
            if (!url)
                continue;
            const inlineData = await imageUrlToInlineData(url);
            if (inlineData)
                parts.push({ inlineData });
        }
    }
    // Gemini rejects empty `parts`; keep at least one (possibly empty) text part.
    if (parts.length === 0)
        parts.push({ text: '' });
    return parts;
}
// Translate OpenAI messages to Gemini format. Content may arrive as a string,
// null, or the OpenAI multimodal array envelope. System/assistant/tool messages
// flatten to text; user messages additionally carry images as inlineData parts.
async function toGeminiContents(messages, apiKey) {
    const systemMessages = messages
        .filter(m => m.role === 'system')
        .map(m => contentToString(m.content))
        .filter(s => s.length > 0);
    const toolNameByCallId = new Map();
    for (const m of messages) {
        for (const tc of m.tool_calls ?? []) {
            toolNameByCallId.set(tc.id, tc.function.name);
        }
    }
    const contents = (await Promise.all(messages
        .filter(m => m.role !== 'system')
        .map(async (m) => {
        if (m.role === 'assistant') {
            const parts = [];
            const assistantText = contentToString(m.content);
            if (assistantText.length > 0) {
                parts.push({ text: assistantText });
            }
            for (const call of m.tool_calls ?? []) {
                // Prefer a signature the client preserved; otherwise recover the one
                // we cached when this call was first produced (OpenAI-format clients
                // drop the field, so this is the common path for Gemini multi-turn).
                // If neither is available, fall back to Google's documented dummy
                // sentinel so a signature-less replay still passes the strict 400
                // check (parallel calls get it on every part — harmless, since the
                // sentinel means "skip validation").
                const known = call.thought_signature ?? recallThoughtSig(call.id, call.function.name, call.function.arguments);
                if (!known)
                    noteDummyThoughtSignature(call.function.name);
                const sig = known ?? DUMMY_THOUGHT_SIGNATURE;
                parts.push({
                    thoughtSignature: sig,
                    functionCall: {
                        id: call.id,
                        name: call.function.name,
                        args: safeParseObject(call.function.arguments),
                    },
                });
            }
            if (parts.length === 0)
                return null;
            return {
                role: 'model',
                parts,
            };
        }
        if (m.role === 'tool') {
            const toolCallId = m.tool_call_id;
            if (!toolCallId)
                return null;
            const toolName = m.name ?? toolNameByCallId.get(toolCallId) ?? 'tool';
            const response = safeParseObject(contentToString(m.content));
            return {
                role: 'user',
                parts: [{
                        functionResponse: {
                            id: toolCallId,
                            name: toolName,
                            response,
                        },
                    }],
            };
        }
        return {
            role: 'user',
            parts: await userContentToParts(m.content, apiKey),
        };
    })))
        .filter((entry) => entry !== null);
    return {
        contents,
        systemInstruction: systemMessages.length > 0
            ? { parts: [{ text: systemMessages.join('\n\n') }] }
            : undefined,
    };
}
function extractToolCalls(parts) {
    const calls = [];
    if (!parts)
        return calls;
    let fallbackIndex = 0;
    for (const part of parts) {
        if (!part.functionCall?.name)
            continue;
        const id = part.functionCall.id ?? `call_${Date.now()}_${fallbackIndex++}`;
        const args = normalizeGeminiArgs(part.functionCall.args);
        // Cache the signature keyed by the id we hand the client, so when the client
        // echoes this call back (without the signature, as OpenAI format requires)
        // we can re-attach it and Gemini accepts the history.
        rememberThoughtSig(id, part.thoughtSignature, part.functionCall.name, args);
        calls.push({
            id,
            type: 'function',
            function: {
                name: part.functionCall.name,
                arguments: args,
            },
            thought_signature: part.thoughtSignature,
        });
    }
    return calls;
}
function extractText(parts) {
    if (!parts)
        return null;
    const text = parts
        .filter(p => p.thought !== true)
        .map(p => p.text ?? '')
        .join('');
    return text.length > 0 ? text : null;
}
function extractReasoningContent(parts) {
    if (!parts)
        return null;
    const text = parts
        .filter(p => p.thought === true)
        .map(p => p.text ?? '')
        .join('');
    return text.length > 0 ? text : null;
}
function toGeminiStopSequences(stop) {
    if (!stop)
        return undefined;
    return Array.isArray(stop) ? stop : [stop];
}
export class GoogleProvider extends BaseProvider {
    platform = 'google';
    name = 'Google AI Studio';
    timeoutMs;
    constructor(opts = {}) {
        super();
        // PROVIDER_TIMEOUT_GOOGLE wins over the registration default (#547).
        this.timeoutMs = providerTimeoutMs('google', opts.timeoutMs ?? 15000);
    }
    async chatCompletion(apiKey, messages, modelId, options, quotaContext) {
        const translated = await toGeminiContents(messages, apiKey);
        const request = contentsForModel(modelId, translated.contents, translated.systemInstruction);
        const tools = toGeminiTools(options?.tools);
        const body = {
            contents: request.contents,
            generationConfig: {
                temperature: options?.temperature,
                maxOutputTokens: resolveMaxTokens(this.platform, options?.max_tokens, options?.contextBudget),
                topP: options?.top_p,
                stopSequences: toGeminiStopSequences(options?.stop),
                ...toGeminiExtendedConfig(options),
            },
            tools,
            // functionCallingConfig is only valid when real function tools are present;
            // a grounding-only request (just google_search) must omit it. (#59)
            toolConfig: hasFunctionDeclarations(tools) ? toGeminiToolConfig(options?.tool_choice) : undefined,
        };
        if (request.systemInstruction)
            body.systemInstruction = request.systemInstruction;
        const url = `${API_BASE}/models/${modelId}:generateContent`;
        const res = await this.fetchWithTimeout(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
            body: JSON.stringify(body),
            // 'request' bounds: the deadline covers the body read too, so a 200
            // whose body hangs aborts instead of stalling res.json() forever.
        }, options?.timeoutMs ?? this.timeoutMs, { signal: options?.signal, timeoutBounds: 'request' });
        recordQuotaObservationsFromResponse(res, {
            platform: this.platform,
            keyId: quotaContext?.keyId,
            providerAccountId: quotaContext?.providerAccountId,
            modelId,
            quotaPoolKey: quotaContext?.quotaPoolKey,
            endpoint: 'chat/completions',
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw googleHttpError(res, err);
        }
        const data = await res.json();
        const candidate = data.candidates?.[0];
        const parts = candidate?.content?.parts;
        const toolCalls = extractToolCalls(parts);
        const text = extractText(parts);
        const reasoningContent = extractReasoningContent(parts);
        const usage = {
            prompt_tokens: data.usageMetadata?.promptTokenCount ?? 0,
            completion_tokens: data.usageMetadata?.candidatesTokenCount ?? 0,
            total_tokens: data.usageMetadata?.totalTokenCount ?? 0,
        };
        return {
            id: this.makeId(),
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: modelId,
            choices: [{
                    index: 0,
                    message: {
                        role: 'assistant',
                        content: text,
                        ...(reasoningContent ? { reasoning_content: reasoningContent } : {}),
                        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
                    },
                    finish_reason: toolCalls.length > 0 ? 'tool_calls' : toGeminiFinishReason(candidate?.finishReason),
                }],
            usage,
            _routed_via: { platform: 'google', model: modelId },
        };
    }
    async *streamChatCompletion(apiKey, messages, modelId, options, quotaContext) {
        const translated = await toGeminiContents(messages, apiKey);
        const request = contentsForModel(modelId, translated.contents, translated.systemInstruction);
        const tools = toGeminiTools(options?.tools);
        const body = {
            contents: request.contents,
            generationConfig: {
                temperature: options?.temperature,
                maxOutputTokens: resolveMaxTokens(this.platform, options?.max_tokens, options?.contextBudget),
                topP: options?.top_p,
                stopSequences: toGeminiStopSequences(options?.stop),
                ...toGeminiExtendedConfig(options),
            },
            tools,
            toolConfig: hasFunctionDeclarations(tools) ? toGeminiToolConfig(options?.tool_choice) : undefined,
        };
        if (request.systemInstruction)
            body.systemInstruction = request.systemInstruction;
        const url = `${API_BASE}/models/${modelId}:streamGenerateContent?alt=sse`;
        const res = await this.fetchWithTimeout(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
            body: JSON.stringify(body),
            // Default 'headers' bounds: the deadline dies at response headers, and
            // the client signal + stall watchdog own the stream from there.
        }, options?.timeoutMs ?? this.timeoutMs, { signal: options?.signal });
        recordQuotaObservationsFromResponse(res, {
            platform: this.platform,
            keyId: quotaContext?.keyId,
            providerAccountId: quotaContext?.providerAccountId,
            modelId,
            quotaPoolKey: quotaContext?.quotaPoolKey,
            endpoint: 'chat/completions',
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw googleHttpError(res, err);
        }
        const reader = res.body?.getReader();
        if (!reader)
            throw new Error('No response body');
        const decoder = new TextDecoder();
        const id = this.makeId();
        let buffer = '';
        let emittedFinish = false;
        let sawToolCalls = false;
        const seenToolCallKeys = new Set();
        // Same mid-stream inactivity watchdog as readSseStream (#553): this adapter
        // parses Gemini's own frame format, so it reads the body itself and used to
        // have no bound at all on a stalled read. Same first-byte grace as
        // readSseStream too (#584): the chat timeout that bounded the headers also
        // budgets the first read, floored at the stall budget.
        const inactivityTimeoutMs = streamStallTimeoutMs(this.platform);
        const firstByteMs = this.firstByteBudgetMs(options?.timeoutMs ?? this.timeoutMs, inactivityTimeoutMs);
        let awaitingFirstByte = true;
        try {
            while (true) {
                const { done, value } = awaitingFirstByte
                    ? await this.readWithStallTimeout(() => reader.read(), firstByteMs, this.firstByteTimeoutMessage(firstByteMs))
                    : await this.readWithStallTimeout(() => reader.read(), inactivityTimeoutMs);
                awaitingFirstByte = false;
                if (done)
                    break;
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop() ?? '';
                for (const line of lines) {
                    const trimmed = line.trim();
                    // `data:` with or without the space, same as BaseProvider (#1087).
                    if (!trimmed || !trimmed.startsWith('data:'))
                        continue;
                    const raw = trimmed.slice(5).replace(/^ /, '');
                    if (raw === '[DONE]') {
                        if (!emittedFinish) {
                            emittedFinish = true;
                            yield {
                                id,
                                object: 'chat.completion.chunk',
                                created: Math.floor(Date.now() / 1000),
                                model: modelId,
                                choices: [{
                                        index: 0,
                                        delta: {},
                                        finish_reason: sawToolCalls ? 'tool_calls' : 'stop',
                                    }],
                            };
                        }
                        return;
                    }
                    // Skip malformed SSE frames instead of aborting the whole stream.
                    // Matches the defensive parse in openai-compat / cohere / cloudflare:
                    // a single corrupt chunk shouldn't take down the rest of the response.
                    let chunk;
                    try {
                        chunk = JSON.parse(raw);
                    }
                    catch {
                        continue;
                    }
                    const candidate = chunk.candidates?.[0];
                    const parts = candidate?.content?.parts ?? [];
                    const text = extractText(parts);
                    const reasoningContent = extractReasoningContent(parts);
                    const toolCalls = extractToolCalls(parts).filter(call => {
                        const key = `${call.id}:${call.function.name}:${call.function.arguments}`;
                        if (seenToolCallKeys.has(key))
                            return false;
                        seenToolCallKeys.add(key);
                        return true;
                    });
                    if ((text && text.length > 0) || (reasoningContent && reasoningContent.length > 0) || toolCalls.length > 0) {
                        sawToolCalls = sawToolCalls || toolCalls.length > 0;
                        yield {
                            id,
                            object: 'chat.completion.chunk',
                            created: Math.floor(Date.now() / 1000),
                            model: modelId,
                            choices: [{
                                    index: 0,
                                    delta: {
                                        ...(text ? { content: text } : {}),
                                        ...(reasoningContent ? { reasoning_content: reasoningContent } : {}),
                                        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
                                    },
                                    finish_reason: null,
                                }],
                        };
                    }
                    if (candidate?.finishReason && !emittedFinish) {
                        emittedFinish = true;
                        yield {
                            id,
                            object: 'chat.completion.chunk',
                            created: Math.floor(Date.now() / 1000),
                            model: modelId,
                            choices: [{
                                    index: 0,
                                    delta: {},
                                    finish_reason: sawToolCalls ? 'tool_calls' : toGeminiFinishReason(candidate.finishReason),
                                }],
                        };
                        return;
                    }
                }
            }
        }
        finally {
            // Runs on normal completion, on the early returns above, AND when the
            // consumer abandons the generator mid-stream (a client disconnect breaks
            // the route pump's for-await, which calls gen.return() at the yield
            // point). Without it the Gemini generation kept running upstream —
            // quota burning with nobody reading — because this adapter reads the
            // body itself instead of going through readSseStream's shared cleanup.
            reader.cancel().catch(() => { });
        }
        // Reaching here means the body ended with neither `[DONE]` nor any
        // `finishReason` — both legitimate terminators `return` from inside the
        // loop above, so the only way out to this point is the `if (done) break`
        // on an abrupt EOF (an h2 END_STREAM from an edge, or the backend cutting
        // the generation mid-answer).
        //
        // This used to synthesize `finish_reason: 'stop'`, which told the client a
        // half-written answer had completed normally: no failover, the request row
        // logged 'success', and the route never benched. base.ts:392-397 states the
        // opposite contract for every adapter that goes through readSseStream —
        // "a stream that ends without [DONE] AND without any finish_reason is a
        // truncated generation, not a completion" — and throws (base.ts:471). This
        // adapter parses Gemini's own frame format and reads the body itself, so it
        // never inherited that. Throw the same message: isStreamTruncatedError
        // (lib/error-classify.ts:685) matches on it, and the fallback loop already
        // fails over and bench-counts the streak (lib/fallback-loop.ts:485).
        if (!emittedFinish) {
            throw new Error(`${this.name} stream ended unexpectedly (no [DONE], no finish_reason) — connection reset or truncated upstream`);
        }
    }
    async validateKey(apiKey, quotaContext) {
        // Transport errors propagate — health.ts marks status='error' without
        // counting toward auto-disable.
        const res = await this.fetchWithTimeout(`${API_BASE}/models`, { method: 'GET', headers: { 'x-goog-api-key': apiKey } }, 10000, { timeoutBounds: 'request' });
        recordQuotaObservationsFromResponse(res, {
            platform: this.platform,
            keyId: quotaContext?.keyId,
            providerAccountId: quotaContext?.providerAccountId,
            modelId: quotaContext?.modelId,
            quotaPoolKey: quotaContext?.quotaPoolKey,
            endpoint: 'models',
        });
        if (res.ok)
            return true;
        let body = null;
        try {
            body = (await res.json());
        }
        catch { /* non-JSON error body */ }
        const err = body?.error;
        const details = Array.isArray(err?.details) ? err.details : [];
        const reason = details.find(d => typeof d?.reason === 'string')?.reason;
        const message = typeof err?.message === 'string' ? err.message : '';
        const gStatus = typeof err?.status === 'string' ? err.status : undefined;
        const badCredentials = res.status === 401 ||
            reason === 'API_KEY_INVALID' ||
            /API key not valid|API key expired|API_KEY_INVALID/i.test(message);
        if (badCredentials) {
            console.warn(`[Google] validateKey: key rejected as invalid (HTTP ${res.status}${reason ? ` ${reason}` : ''})`);
            return {
                valid: false,
                error: `Google key validation failed (HTTP ${res.status}${reason ? ` ${reason}` : ''})${message ? `: ${message}` : ''}`,
            };
        }
        console.warn(`[Google] validateKey: inconclusive HTTP ${res.status} (${gStatus ?? 'UNKNOWN'}${reason ? `/${reason}` : ''}): ${message.slice(0, 200)} ` +
            `— treating as 'error', not auto-disabling (the key may be valid but blocked by region/permission/restriction on this host).`);
        throw new Error(`Google key validation inconclusive (HTTP ${res.status}${gStatus ? ` ${gStatus}` : ''}${reason ? ` ${reason}` : ''})` +
            `${message ? `: ${message}` : ''}`);
    }
}
//# sourceMappingURL=google.js.map