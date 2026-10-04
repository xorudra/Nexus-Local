import { Router } from 'express';
import { z } from 'zod';
import { COMPRESSION_MODES } from '../services/compression/types.js';
import { compressRequest } from '../services/compression/pipeline.js';
import { getCompressionConfig } from '../services/compression/config.js';
import { getCompressionStats } from '../services/compression/stats.js';
export const compressionRouter = Router();
const previewMessageSchema = z.object({
    role: z.enum(['system', 'user', 'assistant', 'tool']),
    content: z.union([
        z.string(),
        z.null(),
        z.array(z.union([z.string(), z.record(z.string(), z.unknown())])),
    ]),
    name: z.string().optional(),
    tool_call_id: z.string().optional(),
    tool_calls: z.array(z.object({
        id: z.string(),
        type: z.literal('function'),
        function: z.object({ name: z.string(), arguments: z.string() }),
    }).passthrough()).optional(),
}).passthrough();
compressionRouter.get('/stats', (_req, res) => {
    res.json({ config: getCompressionConfig(), ...getCompressionStats() });
});
function previewMessages(body) {
    if (typeof body === 'string')
        return [{ role: 'user', content: body }];
    if (!body || typeof body !== 'object')
        return null;
    const value = body;
    if (Array.isArray(value.messages)) {
        const parsed = z.array(previewMessageSchema).safeParse(value.messages);
        return parsed.success ? parsed.data : null;
    }
    if (typeof value.body === 'string')
        return [{ role: 'user', content: value.body }];
    if (value.body && typeof value.body === 'object' && Array.isArray(value.body.messages)) {
        const parsed = z.array(previewMessageSchema).safeParse(value.body.messages);
        return parsed.success ? parsed.data : null;
    }
    return null;
}
compressionRouter.post('/preview', (req, res) => {
    const messages = previewMessages(req.body);
    if (!messages || messages.length === 0) {
        res.status(400).json({
            error: {
                message: 'Preview requires `messages`, a request `body` containing messages, or a string `body`.',
                type: 'invalid_request_error',
            },
        });
        return;
    }
    const rawMode = req.body?.mode;
    const mode = typeof rawMode === 'string'
        && COMPRESSION_MODES.includes(rawMode)
        ? rawMode
        : getCompressionConfig().mode;
    const targetTokens = req.body?.targetTokens;
    const tools = Array.isArray(req.body?.tools)
        ? req.body.tools
        : undefined;
    const result = compressRequest(messages, {
        previewMode: mode,
        targetTokens: typeof targetTokens === 'number' && targetTokens > 0 ? Math.floor(targetTokens) : undefined,
        tools,
        recordStats: false,
    });
    res.json({
        mode: result.mode,
        original: messages,
        compressed: result.messages,
        diff: {
            beforeChars: result.stats.originalChars,
            afterChars: result.stats.compressedChars,
            savedChars: result.stats.originalChars - result.stats.compressedChars,
        },
        stats: result.stats,
    });
});
//# sourceMappingURL=compression.js.map