// Request-scoped media security screening for chat attachments.
//
// Every image / video / link block in an inbound /v1/chat/completions request
// is verified BEFORE routing, so a blocked file never reaches any provider:
//   1. Resolve bytes — data: URIs are decoded; http(s) URLs are fetched
//      server-side through the egress proxy (same posture as the Google
//      adapter's media fetches: http/https only, size-capped, timeout).
//   2. Magic-byte sniffing — the bytes must genuinely be an image or a video.
//      A renamed .exe/.scr/.zip (or any other payload wearing a fake
//      extension or Content-Type) fails here and the request is rejected.
//   3. Per-kind size caps — images 8MB, videos 200MB (the Google adapter
//      handles >20MB videos via the Files API).
//
// `link_url` blocks (the dashboard's universal Link attachment) are rewritten
// in place to `image_url` / `video_url` once verified, so all downstream code
// (vision gates, routing, provider adapters) works unchanged.
//
// Nothing here executes the file — it is only ever decoded or streamed into
// an upstream AI API call — but screening at the door keeps disguised
// malware and garbage out of the pipeline with a clear 422 instead of a
// confusing downstream failure.
import { proxyFetch } from './proxy.js';
export class MediaBlockedError extends Error {
    statusCode = 422;
    code = 'media_blocked';
    constructor(message) {
        super(message);
        this.name = 'MediaBlockedError';
    }
}
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_VIDEO_BYTES = 200 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 120_000;
function sniffMediaKind(buf) {
    if (buf.length < 12)
        return null;
    // --- images ---
    if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff)
        return 'image'; // JPEG
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47)
        return 'image'; // PNG
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38)
        return 'image'; // GIF
    if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP')
        return 'image'; // WebP
    if (buf[0] === 0x42 && buf[1] === 0x4d)
        return 'image'; // BMP
    // --- video ---
    if (buf.toString('ascii', 4, 8) === 'ftyp')
        return 'video'; // MP4 / MOV
    if (buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3)
        return 'video'; // WebM / MKV
    if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'AVI ')
        return 'video'; // AVI
    return null;
}
function decodeDataUrl(url) {
    const m = /^data:([^;,]+)?(;base64)?,(.*)$/s.exec(url);
    if (!m)
        return null;
    try {
        return m[2]
            ? Buffer.from(m[3] ?? '', 'base64')
            : Buffer.from(decodeURIComponent(m[3] ?? ''), 'utf8');
    }
    catch {
        return null;
    }
}
async function fetchMediaBytes(url, label) {
    let res;
    try {
        res = await proxyFetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) }, 'google', 'video', FETCH_TIMEOUT_MS);
    }
    catch {
        throw new MediaBlockedError(`Couldn't download the ${label} link — the server couldn't reach it. Check the URL and try again.`);
    }
    if (!res.ok) {
        throw new MediaBlockedError(`Couldn't download the ${label} link (HTTP ${res.status}). Check the URL and try again.`);
    }
    const buf = Buffer.from(await res.arrayBuffer().catch(() => new ArrayBuffer(0)));
    if (buf.length === 0) {
        throw new MediaBlockedError(`The ${label} link downloaded nothing. Check the URL and try again.`);
    }
    if (buf.length > MAX_VIDEO_BYTES) {
        throw new MediaBlockedError(`That ${label} is larger than 200 MB, which is the biggest file the server can handle.`);
    }
    return buf;
}
function blockUrlOf(block, key) {
    const v = block[key];
    if (typeof v === 'string')
        return v;
    if (v && typeof v.url === 'string')
        return v.url;
    return undefined;
}
function describeSource(url) {
    if (url.startsWith('data:'))
        return 'attached file';
    try {
        return new URL(url).hostname || 'link';
    }
    catch {
        return 'link';
    }
}
/**
 * Screen every image / video / link block in `messages` in place.
 * `link_url` blocks become `image_url` / `video_url` once verified.
 * Throws MediaBlockedError (→ HTTP 422) when anything is unreachable,
 * oversized, or isn't genuinely an image/video.
 */
export async function screenChatMedia(messages) {
    for (const m of messages) {
        const content = m.content;
        if (!Array.isArray(content))
            continue;
        for (const raw of content) {
            const block = raw;
            const type = block?.type;
            const isImage = type === 'image_url' || type === 'image';
            const isVideo = type === 'video_url' || type === 'video';
            const isLink = type === 'link_url' || type === 'link';
            if (!isImage && !isVideo && !isLink)
                continue;
            const key = isImage ? 'image_url' : isVideo ? 'video_url' : 'link_url';
            const url = blockUrlOf(block, key) ?? (isLink ? blockUrlOf(block, 'link') : undefined);
            if (!url) {
                throw new MediaBlockedError('An attachment is missing its file. Try attaching it again.');
            }
            const label = isLink ? 'link' : isVideo ? 'video' : 'photo';
            const source = describeSource(url);
            let buf = null;
            if (url.startsWith('data:')) {
                buf = decodeDataUrl(url);
                if (!buf || buf.length === 0) {
                    throw new MediaBlockedError(`The ${label} from ${source} couldn't be read. Try attaching it again.`);
                }
            }
            else if (/^https?:\/\//i.test(url)) {
                buf = await fetchMediaBytes(url, label);
            }
            else {
                throw new MediaBlockedError(`Only http(s) links can be attached. (${source})`);
            }
            const kind = sniffMediaKind(buf);
            if (!kind) {
                throw new MediaBlockedError(`Blocked for safety: the ${label} from ${source} doesn't look like a real photo or video file. ` +
                    `It may be mislabeled or contain something else.`);
            }
            const cap = kind === 'image' ? MAX_IMAGE_BYTES : MAX_VIDEO_BYTES;
            if (buf.length > cap) {
                throw new MediaBlockedError(kind === 'image'
                    ? `That photo is bigger than 8 MB. Compress it or share it as a link instead.`
                    : `That video is larger than 200 MB, which is the biggest file the server can handle.`);
            }
            if (isImage && kind !== 'image') {
                throw new MediaBlockedError(`Blocked for safety: the photo from ${source} isn't actually an image file.`);
            }
            if (isVideo && kind !== 'video') {
                throw new MediaBlockedError(`Blocked for safety: the video from ${source} isn't actually a video file.`);
            }
            if (isLink) {
                // Universal link: rewrite to the verified kind so routing, the
                // vision/video gates, and every provider adapter just work.
                const newType = kind === 'image' ? 'image_url' : 'video_url';
                const newKey = kind === 'image' ? 'image_url' : 'video_url';
                delete block['link_url'];
                delete block['link'];
                block.type = newType;
                block[newKey] = { url };
            }
        }
    }
}
//# sourceMappingURL=media-screen.js.map