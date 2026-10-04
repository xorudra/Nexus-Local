export declare class MediaBlockedError extends Error {
    readonly statusCode = 422;
    readonly code = "media_blocked";
    constructor(message: string);
}
/**
 * Screen every image / video / link block in `messages` in place.
 * `link_url` blocks become `image_url` / `video_url` once verified.
 * Throws MediaBlockedError (→ HTTP 422) when anything is unreachable,
 * oversized, or isn't genuinely an image/video.
 */
export declare function screenChatMedia(messages: Array<{
    content?: unknown;
}>): Promise<void>;
//# sourceMappingURL=media-screen.d.ts.map